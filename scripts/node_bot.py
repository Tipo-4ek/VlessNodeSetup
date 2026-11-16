#!/usr/bin/env python3
"""Admin-only Telegram access bot and per-user Xray subscriptions.

All credentials and addresses come from the environment or generated state.
The HTTP listener is loopback-only; put a TLS reverse proxy in front of it.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen
import uuid


INBOUND_TAG = "reality-in"
USER_PREFIX = "vns:"
NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")


@dataclass(frozen=True)
class Config:
    bot_token: str
    admin_ids: frozenset[int]
    public_host: str
    reality_public_key: str
    reality_sni: str
    reality_short_id: str
    reality_port: int
    subscription_port: int
    xray_config: Path
    state: Path
    shadowrocket_config: Path = Path("/etc/vless-node-setup/shadowrocket.conf")

    @classmethod
    def from_env(cls) -> Config:
        def required(key: str) -> str:
            value = os.environ.get(key, "").strip()
            if not value:
                raise ValueError(f"{key} is required")
            return value

        def port(key: str) -> int:
            value = int(required(key))
            if not 1 <= value <= 65535:
                raise ValueError(f"{key} must be a TCP port")
            return value

        ids = frozenset(int(part.strip()) for part in required("VNS_ADMIN_IDS").split(","))
        if not ids or any(item <= 0 for item in ids):
            raise ValueError("VNS_ADMIN_IDS must contain positive numeric IDs")
        host = required("VNS_PUBLIC_HOST")
        sni = required("VNS_REALITY_SNI")
        if any(char in host for char in "/:@?# ") or any(char in sni for char in "/:@?# "):
            raise ValueError("host and SNI must be hostnames or IP literals")
        return cls(
            bot_token=required("VNS_BOT_TOKEN"),
            admin_ids=ids,
            public_host=host,
            reality_public_key=required("VNS_REALITY_PUBLIC_KEY"),
            reality_sni=sni,
            reality_short_id=required("VNS_REALITY_SHORT_ID"),
            reality_port=port("VNS_REALITY_PORT"),
            subscription_port=port("VNS_SUBSCRIPTION_PORT"),
            xray_config=Path(os.environ.get("VNS_XRAY_CONFIG", "/etc/vless-node-setup/xray.json")),
            state=Path(os.environ.get("VNS_STATE", "/var/lib/vless-node-setup/users.json")),
            shadowrocket_config=Path(os.environ.get(
                "VNS_SHADOWROCKET_CONFIG", "/etc/vless-node-setup/shadowrocket.conf"
            )),
        )


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def encoded_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def generation(account_uuid: str) -> str:
    """Short non-secret identifier binding old inline buttons to one account."""
    return hashlib.sha256(account_uuid.encode("ascii")).hexdigest()[:12]


class StaleCardError(ValueError):
    pass


def xray_restart() -> None:
    service = "vless-node-xray"
    result = subprocess.run(
        ["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "restart", service],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode:
        raise RuntimeError("Xray restart failed")
    # Type=simple can report a successful start job before the process exits.
    # Require it to remain active over a short bounded observation window.
    for delay in (0.3, 0.7, 1.0):
        time.sleep(delay)
        status = subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", service],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if status.returncode:
            raise RuntimeError("Xray is not active after restart")


def xray_validate(path: Path) -> None:
    result = subprocess.run(
        [os.environ.get("VNS_XRAY_BIN", "/usr/local/bin/xray"), "run", "-test", "-config", str(path)],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if result.returncode:
        raise RuntimeError("Xray rejected the updated configuration")


class AccessManager:
    """Owns managed clients in one inbound and their private bearer tokens."""

    def __init__(
        self,
        config: Config,
        *,
        restart: Callable[[], None] = xray_restart,
        validate: Callable[[Path], None] = xray_validate,
    ) -> None:
        self.config = config
        self.restart = restart
        self.validate = validate
        self.lock = threading.RLock()

    def _read(self) -> tuple[dict, dict, bytes, bytes | None]:
        config_bytes = self.config.xray_config.read_bytes()
        xray = json.loads(config_bytes)
        state_bytes = self.config.state.read_bytes() if self.config.state.exists() else None
        state = json.loads(state_bytes) if state_bytes is not None else {"users": {}}
        if not isinstance(state, dict) or not isinstance(state.get("users"), dict):
            raise ValueError("Invalid state file")
        if not isinstance(xray, dict) or not isinstance(xray.get("inbounds"), list):
            raise ValueError("Invalid Xray configuration")
        return xray, state, config_bytes, state_bytes

    @staticmethod
    def _clients(xray: dict) -> list:
        matches = [item for item in xray["inbounds"] if item.get("tag") == INBOUND_TAG]
        if len(matches) != 1:
            raise ValueError("Expected exactly one reality-in inbound")
        settings = matches[0].get("settings")
        if not isinstance(settings, dict) or not isinstance(settings.get("clients"), list):
            raise ValueError("The inbound must contain settings.clients")
        return settings["clients"]

    def _commit(self, xray: dict, state: dict, old_config: bytes, old_state: bytes | None) -> None:
        changed_config = False
        try:
            atomic_write(self.config.xray_config, encoded_json(xray))
            changed_config = True
            self.validate(self.config.xray_config)
            atomic_write(self.config.state, encoded_json(state))
            self.restart()
        except Exception as exc:
            if changed_config:
                atomic_write(self.config.xray_config, old_config)
                if old_state is None:
                    self.config.state.unlink(missing_ok=True)
                else:
                    atomic_write(self.config.state, old_state)
                try:
                    self.restart()
                except Exception as recovery_exc:
                    raise RuntimeError("Update failed; previous configuration restored, but Xray recovery failed") from recovery_exc
            raise RuntimeError("Update failed; previous configuration restored") from exc

    def reconcile_startup(self) -> None:
        """Rebuild managed Xray clients from committed state after a crash."""
        with self.lock:
            xray, state, _, _ = self._read()
            clients = self._clients(xray)
            desired: list[dict] = []
            seen_uuids: set[str] = set()
            seen_tokens: set[str] = set()
            for name, user in sorted(state["users"].items()):
                if not isinstance(name, str) or not NAME_RE.fullmatch(name) or not isinstance(user, dict):
                    raise ValueError("Invalid managed account state")
                if not isinstance(user.get("active"), bool):
                    raise ValueError("Invalid managed account state")
                if not user["active"]:
                    continue
                account_uuid = user.get("uuid")
                token = user.get("token")
                try:
                    uuid.UUID(account_uuid)
                except (TypeError, ValueError, AttributeError) as exc:
                    raise ValueError("Invalid managed account state") from exc
                if (account_uuid in seen_uuids or not isinstance(token, str)
                        or not TOKEN_RE.fullmatch(token) or token in seen_tokens):
                    raise ValueError("Invalid managed account state")
                seen_uuids.add(account_uuid)
                seen_tokens.add(token)
                desired.append({"id": account_uuid, "flow": "xtls-rprx-vision",
                                "email": USER_PREFIX + name})
            if not all(isinstance(item, dict) for item in clients):
                raise ValueError("Invalid Xray client list")
            unmanaged = [item for item in clients
                         if not str(item.get("email", "")).startswith(USER_PREFIX)]
            if len(unmanaged) + len(desired) != len(clients) or clients != unmanaged + desired:
                clients[:] = unmanaged + desired
                atomic_write(self.config.xray_config, encoded_json(xray))
            self.validate(self.config.xray_config)
            self.restart()

    def add(self, name: str) -> dict:
        if not NAME_RE.fullmatch(name):
            raise ValueError("Name must contain 1–32 ASCII letters, digits, underscores or hyphens")
        with self.lock:
            xray, state, old_config, old_state = self._read()
            clients = self._clients(xray)
            if name in state["users"] and state["users"][name].get("active"):
                user = state["users"][name]
                owned = [item for item in clients if item.get("email") == USER_PREFIX + name]
                if len(owned) == 1 and owned[0].get("id") == user.get("uuid"):
                    # A Telegram update may be retried after a reply failure.
                    return dict(user)
                raise ValueError("Managed client and state do not match")
            if any(item.get("email") == USER_PREFIX + name for item in clients):
                raise ValueError("A client with this name already exists")
            user = {"uuid": str(uuid.uuid4()), "token": secrets.token_urlsafe(32), "active": True}
            clients.append({"id": user["uuid"], "flow": "xtls-rprx-vision", "email": USER_PREFIX + name})
            state["users"][name] = user
            self._commit(xray, state, old_config, old_state)
            return dict(user)

    def revoke(self, name: str, *, expected_generation: str | None = None) -> bool:
        if not NAME_RE.fullmatch(name):
            raise ValueError("Invalid name")
        with self.lock:
            xray, state, old_config, old_state = self._read()
            user = state["users"].get(name)
            if not user or not user.get("active"):
                if expected_generation is not None:
                    raise StaleCardError("This card is outdated")
                return False
            if expected_generation is not None and generation(user["uuid"]) != expected_generation:
                raise StaleCardError("This card is outdated")
            clients = self._clients(xray)
            matches = [item for item in clients if item.get("email") == USER_PREFIX + name]
            if len(matches) != 1 or matches[0].get("id") != user["uuid"]:
                raise ValueError("Managed client and state do not match")
            clients.remove(matches[0])
            user["active"] = False
            self._commit(xray, state, old_config, old_state)
            return True

    def list_users(self) -> list[str]:
        with self.lock:
            _, state, _, _ = self._read()
            return sorted(name for name, user in state["users"].items() if user.get("active"))

    def get(self, name: str) -> dict | None:
        with self.lock:
            xray, state, _, _ = self._read()
            user = state["users"].get(name)
            if not user or not user.get("active"):
                return None
            owned = [item for item in self._clients(xray) if item.get("email") == USER_PREFIX + name]
            if len(owned) != 1 or owned[0].get("id") != user["uuid"]:
                return None
            return dict(user)

    def by_token(self, token: str) -> tuple[str, dict] | None:
        if not TOKEN_RE.fullmatch(token):
            return None
        with self.lock:
            xray, state, _, _ = self._read()
            clients = self._clients(xray)
            for name, user in state["users"].items():
                if not isinstance(user, dict) or not user.get("active"):
                    continue
                if not secrets.compare_digest(str(user.get("token", "")), token):
                    continue
                owned = [item for item in clients if item.get("email") == USER_PREFIX + name]
                if len(owned) == 1 and owned[0].get("id") == user.get("uuid"):
                    return name, dict(user)
            return None

    def uri(self, name: str, user: dict) -> str:
        cfg = self.config
        params = urlencode({
            "encryption": "none", "flow": "xtls-rprx-vision", "security": "reality",
            "sni": cfg.reality_sni, "fp": "chrome", "pbk": cfg.reality_public_key,
            "sid": cfg.reality_short_id, "type": "tcp",
        })
        return f"vless://{user['uuid']}@{cfg.public_host}:{cfg.reality_port}?{params}#{quote(name)}"

    def links(self, name: str, user: dict) -> str:
        host = self.config.public_host
        return (f"{self.uri(name, user)}\n"
                f"Subscription: https://{host}/sub/{user['token']}\n"
                f"Shadowrocket rules: https://{host}/shadowrocket/{user['token']}")


def make_handler(manager: AccessManager) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            match = re.fullmatch(r"/(sub|shadowrocket)/([A-Za-z0-9_-]{32,128})", parts.path)
            if not match or parts.query or parts.fragment:
                self.send_error(404)
                return
            found = manager.by_token(match.group(2))
            if found is None:
                self.send_error(404)
                return
            if match.group(1) == "sub":
                name, user = found
                body = base64.b64encode((manager.uri(name, user) + "\n").encode("utf-8"))
                content_type = "text/plain; charset=utf-8"
            else:
                try:
                    body = manager.config.shadowrocket_config.read_bytes()
                except OSError:
                    self.send_error(503)
                    return
                if not body:
                    self.send_error(503)
                    return
                content_type = "text/plain; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            # The URL contains a bearer token; never put it in a request log.
            pass

    return Handler


def telegram_api(cfg: Config, method: str, payload: dict) -> dict:
    url = f"https://api.telegram.org/bot{cfg.bot_token}/{method}"
    request = Request(url, data=urlencode(payload).encode("utf-8"), method="POST")
    try:
        with urlopen(request, timeout=35) as response:
            data = json.load(response)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError("Telegram request failed") from exc
    if not isinstance(data, dict) or not data.get("ok"):
        raise RuntimeError("Telegram request failed")
    return data


def command(manager: AccessManager, text: str) -> str:
    parts = text.strip().split()
    if not parts:
        return "Commands: /add NAME, /list, /show NAME, /revoke NAME"
    verb = parts[0].split("@", 1)[0]
    if verb in ("/start", "/help") and len(parts) == 1:
        return "Commands: /add NAME, /list, /show NAME, /revoke NAME"
    if verb == "/list" and len(parts) == 1:
        names = manager.list_users()
        return "Active users: " + (", ".join(names) if names else "none")
    if verb == "/add" and len(parts) == 2:
        user = manager.add(parts[1])
        return manager.links(parts[1], user)
    if verb == "/show" and len(parts) == 2:
        user = manager.get(parts[1])
        return manager.links(parts[1], user) if user else "No active access for that name"
    if verb == "/revoke" and len(parts) == 2:
        return "Access revoked" if manager.revoke(parts[1]) else "No active access for that name"
    return "Commands: /add NAME, /list, /show NAME, /revoke NAME"


def button(label: str, action: str) -> dict[str, str]:
    return {"text": label, "callback_data": action}


def card(manager: AccessManager, action: str) -> tuple[str, list[list[dict[str, str]]]]:
    """Build a fresh card from current state; never cache per-user credentials."""
    if action == "menu":
        return (
            "VlessNodeSetup\nChoose an action. Add a user with /add NAME.",
            [[button("Users", "users")], [button("Help", "help")]],
        )
    if action == "help":
        return (
            "Commands: /add NAME, /list, /show NAME, /revoke NAME",
            [[button("Back", "menu")]],
        )
    if action == "users":
        names = manager.list_users()
        rows = [[button(name, f"user:{name}")] for name in names]
        rows.append([button("Back", "menu")])
        return ("Active users" if names else "No active users. Add one with /add NAME.", rows)
    parts = action.split(":")
    if len(parts) == 2 and parts[0] == "user" and NAME_RE.fullmatch(parts[1]):
        name = parts[1]
        user = manager.get(name)
        if user is None:
            return ("No active access for that name", [[button("Users", "users")]])
        version = generation(user["uuid"])
        return (
            f"Access for {name}\n{manager.links(name, user)}",
            [[button("Revoke access", f"revoke:{name}:{version}")], [button("Users", "users")]],
        )
    if (len(parts) == 3 and parts[0] in {"revoke", "confirm", "cancel"}
            and NAME_RE.fullmatch(parts[1]) and re.fullmatch(r"[a-f0-9]{12}", parts[2])):
        prefix, name, version = parts
        user = manager.get(name)
        if user is None or generation(user["uuid"]) != version:
            return ("This card is outdated. Open the current user card.", [[button("Users", "users")]])
        if prefix == "cancel":
            return card(manager, f"user:{name}")
        if prefix == "revoke":
            return (
                f"Revoke access for {name}?",
                [[button("Yes, revoke", f"confirm:{name}:{version}"),
                  button("Cancel", f"cancel:{name}:{version}")]],
            )
        try:
            manager.revoke(name, expected_generation=version)
        except StaleCardError:
            return ("This card is outdated. Open the current user card.", [[button("Users", "users")]])
        return (f"Access revoked for {name}", [[button("Users", "users")]])
    return ("Unknown action", [[button("Menu", "menu")]])


def send_card(cfg: Config, chat_id: int, text: str, rows: list[list[dict[str, str]]],
              *, message_id: int | None = None) -> None:
    payload: dict[str, object] = {
        "chat_id": chat_id, "text": text,
        "reply_markup": json.dumps({"inline_keyboard": rows}),
    }
    if message_id is None:
        telegram_api(cfg, "sendMessage", payload)
        return
    payload["message_id"] = message_id
    try:
        telegram_api(cfg, "editMessageText", payload)
    except RuntimeError:
        # Telegram may reject an edit of an old or unchanged message.
        payload.pop("message_id")
        telegram_api(cfg, "sendMessage", payload)


def process_update(manager: AccessManager, update: dict) -> None:
    callback = update.get("callback_query")
    if isinstance(callback, dict):
        callback_id = callback.get("id")
        if not isinstance(callback_id, str):
            return
        sender = callback.get("from", {})
        message = callback.get("message", {})
        chat = message.get("chat", {}) if isinstance(message, dict) else {}
        allowed = (isinstance(sender, dict) and sender.get("id") in manager.config.admin_ids
                   and isinstance(chat, dict) and chat.get("type") == "private"
                   and chat.get("id") == sender.get("id"))
        acknowledgement = {"callback_query_id": callback_id}
        if not allowed:
            acknowledgement["text"] = "Not authorized"
        telegram_api(manager.config, "answerCallbackQuery", acknowledgement)
        if not allowed:
            return
        action = callback.get("data")
        if not isinstance(action, str) or len(action) > 64:
            return
        try:
            text, rows = card(manager, action)
        except (ValueError, RuntimeError, OSError, json.JSONDecodeError):
            text, rows = "Operation failed; see local service status", [[button("Menu", "menu")]]
        send_card(manager.config, chat["id"], text, rows, message_id=message.get("message_id"))
        return
    message = update.get("message")
    if not isinstance(message, dict):
        return
    sender = message.get("from", {})
    chat = message.get("chat", {})
    if (sender.get("id") not in manager.config.admin_ids
            or chat.get("type") != "private" or chat.get("id") != sender.get("id")):
        return
    text = message.get("text")
    if not isinstance(text, str) or not text.startswith("/"):
        return
    try:
        parts = text.strip().split()
        verb = parts[0].split("@", 1)[0] if parts else ""
        if verb in ("/start", "/help") and len(parts) == 1:
            reply, rows = card(manager, "menu" if verb == "/start" else "help")
        elif verb == "/list" and len(parts) == 1:
            reply, rows = card(manager, "users")
        elif verb == "/show" and len(parts) == 2:
            reply, rows = card(manager, f"user:{parts[1]}")
        elif verb == "/add" and len(parts) == 2:
            manager.add(parts[1])
            reply, rows = card(manager, f"user:{parts[1]}")
        else:
            reply, rows = command(manager, text), None
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        reply, rows = (str(exc) if isinstance(exc, ValueError) else "Operation failed; see local service status"), None
    if rows is None:
        telegram_api(manager.config, "sendMessage", {"chat_id": chat["id"], "text": reply})
    else:
        send_card(manager.config, chat["id"], reply, rows)


def run(cfg: Config) -> None:
    manager = AccessManager(cfg)
    # A prior process may have died after writing files but before restarting Xray.
    # Never expose HTTP or Telegram until the on-disk config is active.
    manager.reconcile_startup()
    if not cfg.shadowrocket_config.is_file():
        raise ValueError("Shadowrocket rule file is missing")
    server = ThreadingHTTPServer(("127.0.0.1", cfg.subscription_port), make_handler(manager))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    offset = 0
    try:
        while True:
            try:
                data = telegram_api(cfg, "getUpdates", {"offset": offset, "timeout": 25,
                                                        "allowed_updates": '["message","callback_query"]'})
                updates = data.get("result", [])
                if not isinstance(updates, list):
                    raise RuntimeError("Invalid Telegram response")
                for update in updates:
                    if not isinstance(update, dict) or not isinstance(update.get("update_id"), int):
                        continue
                    try:
                        process_update(manager, update)
                    except RuntimeError:
                        # Retry on the next poll; do not acknowledge failed delivery.
                        break
                    offset = max(offset, update["update_id"] + 1)
            except RuntimeError:
                time.sleep(3)
    finally:
        server.shutdown()
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate environment and local files")
    args = parser.parse_args()
    try:
        cfg = Config.from_env()
        if args.check:
            manager = AccessManager(cfg)
            xray, _, _, _ = manager._read()
            manager._clients(xray)
            if not cfg.shadowrocket_config.is_file():
                raise ValueError("Shadowrocket rule file is missing")
            print("Configuration OK")
        else:
            run(cfg)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Configuration error: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
