#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  printf 'Run as root with sudo.\n' >&2
  exit 1
fi

systemctl disable --now vless-node-bot.service vless-node-xray.service >/dev/null 2>&1 || true
rm -f -- /etc/systemd/system/vless-node-bot.service \
  /etc/systemd/system/vless-node-xray.service /etc/sudoers.d/vless-node-bot
systemctl daemon-reload

if [[ -f /etc/caddy/Caddyfile ]] && grep -q '^# Managed by VlessNodeSetup$' /etc/caddy/Caddyfile; then
  systemctl disable --now caddy.service >/dev/null 2>&1 || true
  rm -f -- /etc/caddy/Caddyfile
fi

rm -f -- /opt/vless-node-setup/scripts/node_bot.py
rmdir -- /opt/vless-node-setup/scripts /opt/vless-node-setup 2>/dev/null || true

printf 'Services removed. Private keys, user state, configuration and installed packages were retained in /etc/vless-node-setup and /var/lib/vless-node-setup.\n'
