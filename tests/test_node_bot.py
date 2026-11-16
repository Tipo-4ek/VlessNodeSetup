from __future__ import annotations

import base64
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import node_bot as bot  # noqa: E402


class NodeBotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.xray = root / "xray.json"
        self.state = root / "users.json"
        self.shadowrocket = root / "shadowrocket.conf"
        self.shadowrocket.write_text("[Rule]\nDOMAIN-SUFFIX,youtube.com,PROXY\nGEOIP,RU,DIRECT\n", encoding="utf-8")
        self.xray.write_text(json.dumps({
            "inbounds": [{"tag": "reality-in", "settings": {"clients": []}}],
            "outbounds": [{"protocol": "freedom"}],
        }), encoding="utf-8")
        self.cfg = bot.Config(
            bot_token="test-token", admin_ids=frozenset({123}),
            public_host="node.example.invalid", reality_public_key="public-key",
            reality_sni="front.example.invalid", reality_short_id="01234567",
            reality_port=8443, subscription_port=0, xray_config=self.xray, state=self.state,
            shadowrocket_config=self.shadowrocket,
        )
        self.restarts = 0

        def restart() -> None:
            self.restarts += 1

        self.manager = bot.AccessManager(self.cfg, restart=restart, validate=lambda _: None)

    def test_individual_access_and_revoke(self) -> None:
        first = self.manager.add("alice")
        second = self.manager.add("bob")
        self.assertNotEqual(first["uuid"], second["uuid"])
        self.assertNotEqual(first["token"], second["token"])
        self.assertEqual(self.manager.list_users(), ["alice", "bob"])
        self.assertEqual(self.manager.by_token(first["token"])[0], "alice")
        self.assertTrue(self.manager.revoke("alice"))
        self.assertIsNone(self.manager.by_token(first["token"]))
        self.assertEqual(self.manager.by_token(second["token"])[0], "bob")
        clients = json.loads(self.xray.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"]
        self.assertEqual([item["email"] for item in clients], ["vns:bob"])
        self.assertFalse(self.manager.revoke("alice"))

    def test_reissued_user_gets_new_credentials(self) -> None:
        old = self.manager.add("alice")
        self.manager.revoke("alice")
        new = self.manager.add("alice")
        self.assertNotEqual(old["uuid"], new["uuid"])
        self.assertNotEqual(old["token"], new["token"])
        self.assertIsNone(self.manager.by_token(old["token"]))

    def test_restart_failure_restores_both_files(self) -> None:
        before = self.xray.read_bytes()
        attempts = 0

        def fail_once() -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("failure")

        manager = bot.AccessManager(self.cfg, restart=fail_once, validate=lambda _: None)
        with self.assertRaisesRegex(RuntimeError, "restored"):
            manager.add("alice")
        self.assertEqual(self.xray.read_bytes(), before)
        self.assertFalse(self.state.exists())
        self.assertEqual(attempts, 2)

    def test_successful_restart_command_with_inactive_service_rolls_back(self) -> None:
        before = self.xray.read_bytes()
        results = [SimpleNamespace(returncode=0), SimpleNamespace(returncode=3),
                   SimpleNamespace(returncode=0),
                   SimpleNamespace(returncode=0), SimpleNamespace(returncode=0),
                   SimpleNamespace(returncode=0)]
        with patch.object(bot.subprocess, "run", side_effect=results) as calls, \
                patch.object(bot.time, "sleep") as sleep:
            manager = bot.AccessManager(self.cfg, restart=bot.xray_restart,
                                        validate=lambda _: None)
            with self.assertRaisesRegex(RuntimeError, "restored"):
                manager.add("alice")
            self.assertEqual(calls.call_count, 6)
            self.assertEqual(calls.call_args_list[1].args[0],
                             ["/usr/bin/systemctl", "is-active", "--quiet", "vless-node-xray"])
            sleep.assert_any_call(0.3)
        self.assertEqual(self.xray.read_bytes(), before)
        self.assertFalse(self.state.exists())

    def test_validation_failure_restores_configuration(self) -> None:
        before = self.xray.read_bytes()
        manager = bot.AccessManager(
            self.cfg, restart=lambda: None,
            validate=lambda _: (_ for _ in ()).throw(RuntimeError("bad config")),
        )
        with self.assertRaisesRegex(RuntimeError, "restored"):
            manager.add("alice")
        self.assertEqual(self.xray.read_bytes(), before)
        self.assertFalse(self.state.exists())

    def test_startup_reconciles_disk_before_serving_and_fails_closed(self) -> None:
        self.manager.add("alice")
        calls: list[str] = []

        def validate(_: Path) -> None:
            calls.append("validate")

        def restart() -> None:
            calls.append("restart")

        recovered = bot.AccessManager(self.cfg, restart=restart, validate=validate)
        recovered.reconcile_startup()
        self.assertEqual(calls, ["validate", "restart"])
        self.assertEqual(recovered.list_users(), ["alice"])

        with patch.object(bot, "AccessManager", return_value=bot.AccessManager(
                self.cfg, restart=lambda: (_ for _ in ()).throw(RuntimeError("restart failed")),
                validate=validate)), patch.object(bot, "ThreadingHTTPServer") as http:
            with self.assertRaises(RuntimeError):
                bot.run(self.cfg)
            http.assert_not_called()
        with patch.object(bot, "AccessManager", return_value=bot.AccessManager(
                self.cfg, restart=restart,
                validate=lambda _: (_ for _ in ()).throw(RuntimeError("validation failed")))), \
                patch.object(bot, "ThreadingHTTPServer") as http:
            with self.assertRaises(RuntimeError):
                bot.run(self.cfg)
            http.assert_not_called()

    def test_add_crash_between_config_and_state_removes_orphan_then_retries(self) -> None:
        before = json.loads(self.xray.read_text(encoding="utf-8"))
        before["inbounds"].append({"tag": "other-in", "settings": {"clients": [{"id": "other"}]}})
        self.xray.write_text(json.dumps(before), encoding="utf-8")
        real_write = bot.atomic_write

        def die_after_config(path: Path, data: bytes, mode: int = 0o600) -> None:
            real_write(path, data, mode)
            if path == self.xray:
                raise KeyboardInterrupt("simulated crash")

        with patch.object(bot, "atomic_write", side_effect=die_after_config):
            with self.assertRaises(KeyboardInterrupt):
                self.manager.add("alice")
        self.assertFalse(self.state.exists())
        self.assertEqual(len(json.loads(self.xray.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"]), 1)
        recovered = bot.AccessManager(self.cfg, restart=lambda: None, validate=lambda _: None)
        recovered.reconcile_startup()
        inbounds = json.loads(self.xray.read_text(encoding="utf-8"))["inbounds"]
        self.assertEqual(inbounds[0]["settings"]["clients"], [])
        self.assertEqual(inbounds[1], before["inbounds"][1])
        fresh = recovered.add("alice")
        self.assertIsNotNone(recovered.by_token(fresh["token"]))

    def test_revoke_crash_between_config_and_state_restores_committed_access(self) -> None:
        old = self.manager.add("alice")
        real_write = bot.atomic_write

        def die_after_config(path: Path, data: bytes, mode: int = 0o600) -> None:
            real_write(path, data, mode)
            if path == self.xray:
                raise KeyboardInterrupt("simulated crash")

        with patch.object(bot, "atomic_write", side_effect=die_after_config):
            with self.assertRaises(KeyboardInterrupt):
                self.manager.revoke("alice")
        self.assertEqual(json.loads(self.xray.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"], [])
        recovered = bot.AccessManager(self.cfg, restart=lambda: None, validate=lambda _: None)
        recovered.reconcile_startup()
        self.assertIsNotNone(recovered.by_token(old["token"]))
        self.assertTrue(recovered.revoke("alice"))
        self.assertIsNone(recovered.by_token(old["token"]))

    def test_revoke_crash_after_state_write_applies_revocation_on_startup(self) -> None:
        old = self.manager.add("alice")
        interrupted = bot.AccessManager(
            self.cfg,
            restart=lambda: (_ for _ in ()).throw(KeyboardInterrupt("simulated crash")),
            validate=lambda _: None,
        )
        with self.assertRaises(KeyboardInterrupt):
            interrupted.revoke("alice")
        self.assertFalse(json.loads(self.state.read_text(encoding="utf-8"))["users"]["alice"]["active"])
        restarts: list[str] = []
        recovered = bot.AccessManager(self.cfg, restart=lambda: restarts.append("restarted"),
                                      validate=lambda _: None)
        recovered.reconcile_startup()
        self.assertEqual(restarts, ["restarted"])
        self.assertIsNone(recovered.by_token(old["token"]))

    def test_inconsistent_state_cannot_serve_subscription(self) -> None:
        user = self.manager.add("alice")
        xray = json.loads(self.xray.read_text(encoding="utf-8"))
        xray["inbounds"][0]["settings"]["clients"] = []
        self.xray.write_text(json.dumps(xray), encoding="utf-8")
        self.assertIsNone(self.manager.by_token(user["token"]))

    def test_duplicate_managed_client_fails_closed(self) -> None:
        user = self.manager.add("alice")
        xray = json.loads(self.xray.read_text(encoding="utf-8"))
        xray["inbounds"][0]["settings"]["clients"].append({"email": "vns:alice", "id": "other"})
        self.xray.write_text(json.dumps(xray), encoding="utf-8")
        self.assertIsNone(self.manager.by_token(user["token"]))
        with self.assertRaisesRegex(ValueError, "do not match"):
            self.manager.revoke("alice")

    def test_http_routes_and_no_store(self) -> None:
        user = self.manager.add("alice")
        server = ThreadingHTTPServer(("127.0.0.1", 0), bot.make_handler(self.manager))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_port}"
        with urlopen(f"{base}/sub/{user['token']}", timeout=2) as response:
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            uri = base64.b64decode(response.read()).decode("utf-8")
            self.assertIn(user["uuid"], uri)
            self.assertIn("node.example.invalid", uri)
        with urlopen(f"{base}/shadowrocket/{user['token']}", timeout=2) as response:
            rules = response.read().decode("utf-8")
            self.assertIn("DOMAIN-SUFFIX,youtube.com,PROXY", rules)
            self.assertIn("GEOIP,RU,DIRECT", rules)
            self.assertNotIn(user["uuid"], rules)
        self.shadowrocket.write_text("[Rule]\nDOMAIN-SUFFIX,youtu.be,PROXY\n", encoding="utf-8")
        with urlopen(f"{base}/shadowrocket/{user['token']}", timeout=2) as response:
            self.assertIn("DOMAIN-SUFFIX,youtu.be,PROXY", response.read().decode("utf-8"))
        self.shadowrocket.unlink()
        with self.assertRaises(HTTPError) as error:
            urlopen(f"{base}/shadowrocket/{user['token']}", timeout=2)
        self.assertEqual(error.exception.code, 503)
        error.exception.close()
        self.manager.revoke("alice")
        for route in ("sub", "shadowrocket"):
            with self.assertRaises(HTTPError) as error:
                urlopen(f"{base}/{route}/{user['token']}", timeout=2)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()

    def test_only_private_admin_commands_are_processed(self) -> None:
        update = {"message": {"from": {"id": 456}, "chat": {"id": 456, "type": "private"}, "text": "/add alice"}}
        with patch.object(bot, "telegram_api") as api:
            bot.process_update(self.manager, update)
            self.assertFalse(self.state.exists())
            api.assert_not_called()
            update["message"]["from"]["id"] = 123
            update["message"]["chat"]["type"] = "group"
            bot.process_update(self.manager, update)
            self.assertFalse(self.state.exists())
            api.assert_not_called()
            update["message"]["chat"]["type"] = "private"
            update["message"]["chat"]["id"] = 123
            bot.process_update(self.manager, update)
            self.assertEqual(self.manager.list_users(), ["alice"])
            api.assert_called_once()

    def callback(self, action: str, *, user_id: int = 123, chat_id: int = 123,
                 chat_type: str = "private") -> dict:
        return {"callback_query": {
            "id": "callback-1", "from": {"id": user_id}, "data": action,
            "message": {"message_id": 7, "chat": {"id": chat_id, "type": chat_type}},
        }}

    def test_unauthorized_callback_cannot_read_or_revoke(self) -> None:
        user = self.manager.add("alice")
        with patch.object(bot, "telegram_api") as api:
            bot.process_update(self.manager, self.callback("user:alice", user_id=456))
            bot.process_update(self.manager, self.callback(
                f"confirm:alice:{bot.generation(user['uuid'])}", chat_type="group"))
            bot.process_update(self.manager, self.callback("user:alice", chat_id=789))
            self.assertEqual([call.args[1] for call in api.call_args_list],
                             ["answerCallbackQuery", "answerCallbackQuery", "answerCallbackQuery"])
            self.assertTrue(self.manager.get("alice"))
            self.assertFalse(any(user["token"] in str(call) for call in api.call_args_list))

    def test_menu_navigation_and_user_card_is_isolated(self) -> None:
        alice = self.manager.add("alice")
        bob = self.manager.add("bob")
        with patch.object(bot, "telegram_api") as api:
            bot.process_update(self.manager, {"message": {
                "from": {"id": 123}, "chat": {"id": 123, "type": "private"}, "text": "/start",
            }})
            self.assertEqual(api.call_args.args[1], "sendMessage")
            self.assertEqual(json.loads(api.call_args.args[2]["reply_markup"])["inline_keyboard"][0][0]["callback_data"], "users")
            api.reset_mock()
            bot.process_update(self.manager, self.callback("users"))
            self.assertEqual([call.args[1] for call in api.call_args_list],
                             ["answerCallbackQuery", "editMessageText"])
            listing = api.call_args.args[2]
            self.assertNotIn(alice["token"], listing["text"])
            self.assertNotIn(bob["token"], listing["text"])
            api.reset_mock()
            bot.process_update(self.manager, self.callback("user:alice"))
            alice_card = api.call_args.args[2]
            self.assertIn(alice["token"], alice_card["text"])
            self.assertNotIn(bob["token"], alice_card["text"])
            self.assertNotIn(bob["uuid"], alice_card["text"])

    def test_revoke_button_requires_confirmation(self) -> None:
        user = self.manager.add("alice")
        version = bot.generation(user["uuid"])
        with patch.object(bot, "telegram_api") as api:
            bot.process_update(self.manager, self.callback(f"revoke:alice:{version}"))
            self.assertIsNotNone(self.manager.by_token(user["token"]))
            prompt = api.call_args.args[2]
            self.assertNotIn(user["token"], prompt["text"])
            buttons = json.loads(prompt["reply_markup"])["inline_keyboard"][0]
            self.assertEqual([item["callback_data"] for item in buttons],
                             [f"confirm:alice:{version}", f"cancel:alice:{version}"])
            bot.process_update(self.manager, self.callback(f"cancel:alice:{version}"))
            self.assertIsNotNone(self.manager.get("alice"))
            bot.process_update(self.manager, self.callback(f"confirm:alice:{version}"))
            self.assertIsNone(self.manager.get("alice"))
            self.assertIsNone(self.manager.by_token(user["token"]))
            self.assertNotIn(user["token"], api.call_args.args[2]["text"])

    def test_stale_confirmation_cannot_revoke_reissued_name(self) -> None:
        old = self.manager.add("alice")
        old_action = f"confirm:alice:{bot.generation(old['uuid'])}"
        self.manager.revoke("alice")
        fresh = self.manager.add("alice")
        with patch.object(bot, "telegram_api") as api:
            bot.process_update(self.manager, self.callback(old_action))
            self.assertIn("outdated", api.call_args.args[2]["text"])
        self.assertEqual(self.manager.get("alice"), fresh)
        self.assertIsNotNone(self.manager.by_token(fresh["token"]))

    def test_confirmation_callback_fits_telegram_limit(self) -> None:
        name = "a" * 32
        user = self.manager.add(name)
        _, rows = bot.card(self.manager, f"user:{name}")
        revoke = rows[0][0]["callback_data"]
        self.assertLessEqual(len(revoke.encode("utf-8")), 64)
        _, rows = bot.card(self.manager, revoke)
        confirm = rows[0][0]["callback_data"]
        self.assertLessEqual(len(confirm.encode("utf-8")), 64)
        self.assertNotIn(user["token"], confirm)

    def test_invalid_names_and_existing_user(self) -> None:
        for name in ("../alice", "alice b", "ä", "a" * 33):
            with self.assertRaises(ValueError):
                self.manager.add(name)
        self.manager.add("alice")
        self.assertEqual(self.manager.add("alice"), self.manager.get("alice"))


if __name__ == "__main__":
    unittest.main()
