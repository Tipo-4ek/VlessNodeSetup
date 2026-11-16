"""Catch obvious private endpoints and access material before publishing.

This scans text only. Screenshots need a separate visual review before commit.
"""

import ipaddress
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".conf", ".env", ".example", ".ini", ".json", ".md", ".py",
    ".service", ".sh", ".txt", ".toml", ".yaml", ".yml",
}
SAFE_DOMAINS = {
    "example.com", "example.net", "example.org", "example.test",
    "github.com", "githubusercontent.com", "telegram.org",
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
    "google.com", "microsoft.com", "xray.dev", "python.org", "pypi.org",
}
DOMAIN_TLDS = {
    "ai", "app", "be", "cc", "cloud", "co", "com", "de", "dev",
    "eu", "fr", "info", "io", "jp", "link", "live", "me", "net",
    "nl", "one", "online", "org", "pro", "ru", "site", "space",
    "store", "su", "tech", "test", "top", "uk", "us", "vpn",
    "website", "win", "xyz",
}
FILE_EXTENSIONS = {
    "conf", "env", "example", "ini", "json", "md", "pem", "py",
    "service", "sh", "txt", "toml", "yaml", "yml",
}
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![\w.-])")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
TELEGRAM_TOKEN = re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b")
ACCESS_URI = re.compile(r"\b(?:vless|vmess|trojan|hysteria2|hy2|ss|ssr)://[^\s<>`\"']+", re.I)


def public_files():
    """Use Git's view of files, including not-yet-staged local additions."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, check=True, capture_output=True,
    )
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = ROOT / raw_path.decode("utf-8", errors="surrogateescape")
        if not path.is_file():
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {".gitignore", "LICENSE", "Dockerfile"}:
            yield path


def unsafe_line(line):
    if TELEGRAM_TOKEN.search(line):
        return "Telegram token"
    for match in ACCESS_URI.finditer(line):
        # Source code can assemble a link from runtime values using braces.
        if "{" not in match.group() and "}" not in match.group():
            return "access URI"
    for match in IPV4.finditer(line):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        if address.is_global and address not in {
            ipaddress.ip_address(".".join(("1",) * 4)),
            ipaddress.ip_address(".".join(("8",) * 4)),
        }:
            return "public IP address"
    for match in DOMAIN.finditer(line):
        domain = match.group().lower()
        tld = domain.rsplit(".", 1)[-1]
        if tld in FILE_EXTENSIONS or tld not in DOMAIN_TLDS:
            continue
        if not any(domain == safe or domain.endswith("." + safe) for safe in SAFE_DOMAINS):
            return "unapproved domain"
    return None


class PublicTreeTest(unittest.TestCase):
    def test_detector(self):
        self.assertEqual(unsafe_line("host=" + ".".join(("203", "0", "113", "10"))), None)
        self.assertEqual(unsafe_line("host=" + ".".join(("198", "51", "100", "10"))), None)
        self.assertEqual(unsafe_line("host=" + ".".join(("93", "184", "216", "34"))), "public IP address")
        self.assertEqual(unsafe_line("server=" + ".".join(("node", "private-domain", "ru"))), "unapproved domain")
        example_host = ".".join(("node", "example", "com"))
        self.assertEqual(unsafe_line("server=" + example_host), None)
        self.assertEqual(unsafe_line("vless" + "://user@" + example_host + ":443"), "access URI")
        self.assertEqual(unsafe_line("f'vless" + "://{user}@{host}:443'"), None)
        self.assertEqual(
            unsafe_line("123456789:" + "A" * 35),
            "Telegram token",
        )

    def test_no_obvious_private_material(self):
        self.assertIn(Path(__file__).resolve(), set(public_files()))
        findings = []
        for path in public_files():
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                reason = unsafe_line(line)
                if reason:
                    findings.append(f"{path.relative_to(ROOT)}:{number}: {reason}")
        self.assertFalse(findings, "Public tree needs review:\n" + "\n".join(findings))


if __name__ == "__main__":
    unittest.main()
