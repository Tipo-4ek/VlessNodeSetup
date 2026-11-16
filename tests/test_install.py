"""Offline checks for the installer inputs; no host services are touched."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InstallerInputsTest(unittest.TestCase):
    def test_reality_template_has_managed_empty_inbound(self):
        config = json.loads((ROOT / "configs/xray.json.template").read_text())
        inbounds = [item for item in config["inbounds"] if item.get("tag") == "reality-in"]
        self.assertEqual(len(inbounds), 1)
        inbound = inbounds[0]
        self.assertEqual(inbound["protocol"], "vless")
        self.assertEqual(inbound["settings"]["clients"], [])
        self.assertEqual(inbound["streamSettings"]["security"], "reality")
        self.assertEqual(inbound["streamSettings"]["network"], "raw")
        reality = inbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["privateKey"], "SET_BY_INSTALLER")
        self.assertIn("target", reality)
        self.assertNotIn("dest", reality)

    def test_bot_service_uses_private_env_and_unprivileged_account(self):
        unit = (ROOT / "configs/node-bot.service").read_text()
        self.assertIn("User=vlessnode", unit)
        self.assertIn("EnvironmentFile=/etc/vless-node-setup/node.env", unit)
        self.assertIn("ExecStart=/usr/bin/python3 /opt/vless-node-setup/scripts/node_bot.py", unit)
        self.assertNotIn("NoNewPrivileges=", unit)
        self.assertNotIn("CapabilityBoundingSet=", unit)
        sudoers = (ROOT / "configs/vless-node-bot.sudoers").read_text().strip()
        self.assertEqual(sudoers, "vlessnode ALL=(root) NOPASSWD: /usr/bin/systemctl restart vless-node-xray")

    def test_example_requires_real_operator_values(self):
        example = (ROOT / "configs/node.env.example").read_text()
        self.assertIn("VNS_BOT_TOKEN=REPLACE_WITH_NEW_BOT_TOKEN", example)
        self.assertIn("VNS_ADMIN_IDS=REPLACE_WITH_YOUR_TELEGRAM_ID", example)
        self.assertIn("VNS_PUBLIC_HOST=node.example.com", example)
        self.assertNotIn("VNS_REALITY_PUBLIC_KEY=", example)

    def test_mihomo_port_matches_installer_default(self):
        env_example = (ROOT / "configs/node.env.example").read_text()
        mihomo_example = (ROOT / "configs/mihomo.yaml.example").read_text()
        self.assertIn("VNS_REALITY_PORT=8443", env_example)
        self.assertIn("    port: 8443", mihomo_example)

    def test_caddy_forwards_subscription_path_unchanged(self):
        installer = (ROOT / "install.sh").read_text()
        self.assertIn("[[ $VNS_SUBSCRIPTION_PORT != 443 && $VNS_SUBSCRIPTION_PORT != 80 ]]", installer)
        self.assertIn("@subscription path /sub/* /shadowrocket/*", installer)
        self.assertIn("handle @subscription {", installer)
        self.assertNotIn("handle_path", installer)
        self.assertIn("reverse_proxy 127.0.0.1:$VNS_SUBSCRIPTION_PORT", installer)
        self.assertIn("log default {\n        output discard", installer)
        self.assertIn("log {\n        output discard", installer)


if __name__ == "__main__":
    unittest.main()
