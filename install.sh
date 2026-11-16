#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh --env-file /path/to/private.env

Installs Xray Reality Vision, a Telegram access bot, and a Caddy HTTPS
subscription endpoint on Debian/Ubuntu. Configure DNS and open TCP 80,
443 and VNS_REALITY_PORT before running. Rerunning updates the software
and service files while preserving user state and Reality keys.
EOF
}

[[ $# -eq 2 && "$1" == --env-file ]] || { usage; exit 2; }
env_file=$2
[[ $EUID -eq 0 ]] || fail 'Run as root with sudo.'
[[ -f $env_file ]] || fail 'The environment file does not exist.'
[[ ! -L $env_file ]] || fail 'Use a regular environment file, not a symlink.'
[[ -z $(find "$env_file" -perm /077 -print -quit) ]] || fail 'The environment file must have mode 0600 or stricter.'
[[ -f /etc/os-release ]] || fail 'Unsupported operating system.'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == debian || ${ID:-} == ubuntu ]] || fail 'Debian or Ubuntu is required.'
command -v apt-get >/dev/null || fail 'apt-get is required.'
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ -f $repo_dir/configs/xray.json.template && -f $repo_dir/scripts/node_bot.py ]] || fail 'Run from a complete checkout.'

# The operator supplies this local shell assignment file. Never print its values.
# shellcheck disable=SC1090
. "$env_file"
: "${VNS_BOT_TOKEN:?Set VNS_BOT_TOKEN in the environment file}"
: "${VNS_ADMIN_IDS:?Set VNS_ADMIN_IDS in the environment file}"
: "${VNS_PUBLIC_HOST:?Set VNS_PUBLIC_HOST in the environment file}"
VNS_REALITY_SNI=${VNS_REALITY_SNI:-www.microsoft.com}
VNS_REALITY_PORT=${VNS_REALITY_PORT:-8443}
VNS_SUBSCRIPTION_PORT=${VNS_SUBSCRIPTION_PORT:-8787}
VNS_XRAY_CONFIG=${VNS_XRAY_CONFIG:-/etc/vless-node-setup/xray.json}
VNS_STATE=${VNS_STATE:-/var/lib/vless-node-setup/users.json}
[[ $VNS_BOT_TOKEN != REPLACE_WITH_NEW_BOT_TOKEN ]] || fail 'Replace the example bot token.'
[[ $VNS_ADMIN_IDS != REPLACE_WITH_YOUR_TELEGRAM_ID ]] || fail 'Replace the example admin ID.'
[[ $VNS_PUBLIC_HOST != *.example.com ]] || fail 'Replace the example public host.'
[[ $VNS_PUBLIC_HOST =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] || fail 'VNS_PUBLIC_HOST must be a DNS hostname.'
[[ $VNS_REALITY_SNI =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] || fail 'VNS_REALITY_SNI must be a DNS hostname.'
[[ $VNS_ADMIN_IDS =~ ^[0-9]+(,[0-9]+)*$ ]] || fail 'VNS_ADMIN_IDS must be comma-separated Telegram IDs.'
[[ $VNS_REALITY_PORT =~ ^[0-9]+$ && $VNS_REALITY_PORT -ge 1024 && $VNS_REALITY_PORT -le 65535 ]] || fail 'VNS_REALITY_PORT must be between 1024 and 65535.'
[[ $VNS_SUBSCRIPTION_PORT =~ ^[0-9]+$ && $VNS_SUBSCRIPTION_PORT -ge 1024 && $VNS_SUBSCRIPTION_PORT -le 65535 ]] || fail 'VNS_SUBSCRIPTION_PORT must be between 1024 and 65535.'
[[ $VNS_SUBSCRIPTION_PORT != 443 && $VNS_SUBSCRIPTION_PORT != 80 ]] || fail 'The subscription backend port must not use Caddy HTTP/HTTPS ports.'
[[ $VNS_REALITY_PORT != "$VNS_SUBSCRIPTION_PORT" && $VNS_REALITY_PORT != 443 && $VNS_REALITY_PORT != 80 ]] || fail 'Reality and subscription/HTTPS ports must not conflict.'
[[ $VNS_XRAY_CONFIG == /etc/vless-node-setup/*.json ]] || fail 'VNS_XRAY_CONFIG must be under /etc/vless-node-setup.'
[[ $VNS_STATE == /var/lib/vless-node-setup/*.json ]] || fail 'VNS_STATE must be under /var/lib/vless-node-setup.'

if systemctl is-active --quiet xray 2>/dev/null; then
  fail 'An existing xray.service is active. Use a fresh server or migrate it manually.'
fi
if [[ -e /etc/caddy/Caddyfile ]] && ! grep -q '^# Managed by VlessNodeSetup$' /etc/caddy/Caddyfile; then
  fail 'An existing Caddyfile would be overwritten. Use a fresh server or migrate it manually.'
fi
for service in nginx apache2; do
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    fail "$service already owns HTTP ports. Use a fresh server or migrate it manually."
  fi
done

info 'Installing operating system packages...'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl python3 openssl caddy sudo

if ! command -v xray >/dev/null; then
  tmp_script=$(mktemp)
  trap 'rm -f -- "$tmp_script"' EXIT
  curl --fail --silent --show-error --location \
    https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh \
    --output "$tmp_script"
  bash "$tmp_script" install
  rm -f -- "$tmp_script"
  trap - EXIT
fi
xray_bin=$(command -v xray)
[[ -x $xray_bin ]] || fail 'Xray installation did not provide an executable.'
systemctl disable --now xray.service >/dev/null 2>&1 || true

id vlessnode >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vless-node-setup \
  --no-create-home --shell /usr/sbin/nologin vlessnode
install -d -m 0750 -o vlessnode -g vlessnode /etc/vless-node-setup /var/lib/vless-node-setup
install -d -m 0755 /opt/vless-node-setup /opt/vless-node-setup/scripts
install -m 0644 "$repo_dir/scripts/node_bot.py" /opt/vless-node-setup/scripts/node_bot.py
if [[ ! -e /etc/vless-node-setup/shadowrocket.conf ]]; then
  install -m 0640 -o vlessnode -g vlessnode \
    "$repo_dir/configs/shadowrocket.conf.example" /etc/vless-node-setup/shadowrocket.conf
fi

# On rerun, keep the key pair. Losing it invalidates every issued client.
if [[ ! -e /etc/vless-node-setup/reality.private ]]; then
  key_output=$("$xray_bin" x25519)
  private_key=$(printf '%s\n' "$key_output" | sed -nE 's/^([Pp]rivate[[:space:]]*[Kk]ey|[Pp]assword):[[:space:]]*//p' | head -n 1)
  public_key=$(printf '%s\n' "$key_output" | sed -nE 's/^([Pp]ublic[[:space:]]*[Kk]ey|[Hh]ash32):[[:space:]]*//p' | head -n 1)
  [[ -n $private_key && -n $public_key ]] || fail 'Could not parse the generated Xray keys.'
  printf '%s' "$private_key" > /etc/vless-node-setup/reality.private
  printf '%s' "$public_key" > /etc/vless-node-setup/reality.public
  chmod 0640 /etc/vless-node-setup/reality.private
  chmod 0644 /etc/vless-node-setup/reality.public
  chown vlessnode:vlessnode /etc/vless-node-setup/reality.private /etc/vless-node-setup/reality.public
  unset key_output private_key public_key
fi
if [[ ! -e /etc/vless-node-setup/reality.short_id ]]; then
  openssl rand -hex 8 > /etc/vless-node-setup/reality.short_id
  chmod 0640 /etc/vless-node-setup/reality.short_id
  chown vlessnode:vlessnode /etc/vless-node-setup/reality.short_id
fi
[[ -s /etc/vless-node-setup/reality.private && -s /etc/vless-node-setup/reality.public && -s /etc/vless-node-setup/reality.short_id ]] || fail 'Reality key material is incomplete. Restore it from backup before rerunning.'

# Preserve existing clients. Existing keys and port/SNI are intentionally not
# rotated by a rerun; migrate them deliberately with a backup instead.
if [[ ! -e $VNS_XRAY_CONFIG ]]; then
  VNS_TEMPLATE="$repo_dir/configs/xray.json.template" \
  VNS_PRIVATE_KEY_FILE=/etc/vless-node-setup/reality.private \
  VNS_SHORT_ID_FILE=/etc/vless-node-setup/reality.short_id \
  VNS_REALITY_SNI="$VNS_REALITY_SNI" VNS_REALITY_PORT="$VNS_REALITY_PORT" \
  VNS_XRAY_CONFIG="$VNS_XRAY_CONFIG" python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path(os.environ['VNS_TEMPLATE'])
c = json.loads(p.read_text(encoding='utf-8'))
i = c['inbounds'][0]
i['port'] = int(os.environ['VNS_REALITY_PORT'])
r = i['streamSettings']['realitySettings']
r['target'] = os.environ['VNS_REALITY_SNI'] + ':443'
r['serverNames'] = [os.environ['VNS_REALITY_SNI']]
r['privateKey'] = pathlib.Path(os.environ['VNS_PRIVATE_KEY_FILE']).read_text().strip()
r['shortIds'] = [pathlib.Path(os.environ['VNS_SHORT_ID_FILE']).read_text().strip()]
target = pathlib.Path(os.environ['VNS_XRAY_CONFIG'])
target.write_text(json.dumps(c, indent=2) + '\n', encoding='utf-8')
PY
  chown vlessnode:vlessnode "$VNS_XRAY_CONFIG"
  chmod 0640 "$VNS_XRAY_CONFIG"
else
  VNS_XRAY_CONFIG="$VNS_XRAY_CONFIG" VNS_REALITY_SNI="$VNS_REALITY_SNI" \
  VNS_REALITY_PORT="$VNS_REALITY_PORT" python3 - <<'PY' || fail 'The existing Xray port/SNI differs from this environment file. Preserve the old values or migrate deliberately.'
import json, os, pathlib
c = json.loads(pathlib.Path(os.environ['VNS_XRAY_CONFIG']).read_text())
matches = [i for i in c['inbounds'] if i.get('tag') == 'reality-in']
assert len(matches) == 1
i = matches[0]
r = i['streamSettings']['realitySettings']
assert i['port'] == int(os.environ['VNS_REALITY_PORT'])
assert r['serverNames'] == [os.environ['VNS_REALITY_SNI']]
assert r['target'] == os.environ['VNS_REALITY_SNI'] + ':443'
PY
fi

"$xray_bin" run -test -config "$VNS_XRAY_CONFIG" >/dev/null 2>&1 || fail 'Xray rejected its configuration.'

if [[ ! -e $VNS_STATE ]]; then
  printf '{"users":{}}\n' > "$VNS_STATE"
  chown vlessnode:vlessnode "$VNS_STATE"
  chmod 0600 "$VNS_STATE"
fi

# systemd EnvironmentFile is root-only; bot and Xray run as an unprivileged user.
node_env_temp=$(mktemp /etc/vless-node-setup/.node.env.XXXXXX)
{
  printf 'VNS_BOT_TOKEN=%s\n' "$VNS_BOT_TOKEN"
  printf 'VNS_ADMIN_IDS=%s\n' "$VNS_ADMIN_IDS"
  printf 'VNS_PUBLIC_HOST=%s\n' "$VNS_PUBLIC_HOST"
  printf 'VNS_REALITY_PUBLIC_KEY=%s\n' "$(cat /etc/vless-node-setup/reality.public)"
  printf 'VNS_REALITY_SNI=%s\n' "$VNS_REALITY_SNI"
  printf 'VNS_REALITY_SHORT_ID=%s\n' "$(cat /etc/vless-node-setup/reality.short_id)"
  printf 'VNS_REALITY_PORT=%s\n' "$VNS_REALITY_PORT"
  printf 'VNS_SUBSCRIPTION_PORT=%s\n' "$VNS_SUBSCRIPTION_PORT"
  printf 'VNS_XRAY_CONFIG=%s\n' "$VNS_XRAY_CONFIG"
  printf 'VNS_XRAY_BIN=%s\n' "$xray_bin"
  printf 'VNS_STATE=%s\n' "$VNS_STATE"
  printf 'VNS_SHADOWROCKET_CONFIG=/etc/vless-node-setup/shadowrocket.conf\n'
} > "$node_env_temp"
chmod 0600 "$node_env_temp"
mv -f -- "$node_env_temp" /etc/vless-node-setup/node.env
set -a
# shellcheck disable=SC1091
. /etc/vless-node-setup/node.env
set +a
/usr/bin/python3 /opt/vless-node-setup/scripts/node_bot.py --check >/dev/null 2>&1 || fail 'Bot configuration check failed.'

cat > /etc/systemd/system/vless-node-xray.service <<EOF
[Unit]
Description=VlessNodeSetup Xray Reality node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vlessnode
Group=vlessnode
ExecStart=$xray_bin run -config $VNS_XRAY_CONFIG
Restart=always
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/vless-node-setup
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF
install -m 0644 "$repo_dir/configs/node-bot.service" /etc/systemd/system/vless-node-bot.service
install -m 0440 "$repo_dir/configs/vless-node-bot.sudoers" /etc/sudoers.d/vless-node-bot
visudo -cf /etc/sudoers.d/vless-node-bot >/dev/null

cat > /etc/caddy/Caddyfile <<EOF
# Managed by VlessNodeSetup
{
    log default {
        output discard
    }
}

$VNS_PUBLIC_HOST {
    encode gzip
    log {
        output discard
    }
    @subscription path /sub/* /shadowrocket/*
    handle @subscription {
        reverse_proxy 127.0.0.1:$VNS_SUBSCRIPTION_PORT
    }
    handle {
        respond 404
    }
}
EOF
chmod 0644 /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 || fail 'Caddy rejected its configuration.'
systemctl daemon-reload
systemctl enable --now vless-node-xray.service vless-node-bot.service caddy.service
systemctl restart vless-node-xray.service vless-node-bot.service
systemctl reload caddy.service
sleep 2
for service in vless-node-xray.service vless-node-bot.service caddy.service; do
  systemctl is-active --quiet "$service" || fail "$service is not active after installation. Inspect its status locally without sharing tokens or URLs."
done
info 'Installed. Open TCP 80, 443 and the Reality port in your cloud firewall.'
info 'Verify DNS, HTTPS certificate issuance, Xray and bot service status before sharing access.'
