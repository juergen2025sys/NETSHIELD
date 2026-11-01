#!/usr/bin/env python3
"""
Tests fuer scripts/dns_list_mirror.py (Parsing und Filter, ohne Netzwerk).

Ausfuehren:
    python3 -m unittest tests.test_dns_list_mirror -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from dns_list_mirror import (  # noqa: E402
    is_protected, normalize_domain, parse_hosts_text, parse_threatfox_csv,
)


class TestNormalizeDomain(unittest.TestCase):
    def test_plain_and_case(self):
        self.assertEqual(normalize_domain("Evil.Example.COM."), "evil.example.com")

    def test_adblock_and_wildcard_syntax(self):
        self.assertEqual(normalize_domain("||bad.example.org^"), "bad.example.org")
        self.assertEqual(normalize_domain("*.bad.example.org"), "bad.example.org")

    def test_rejects_ips_and_local_names(self):
        self.assertIsNone(normalize_domain("1.2.3.4"))
        self.assertIsNone(normalize_domain("::1"))
        self.assertIsNone(normalize_domain("localhost"))

    def test_rejects_invalid(self):
        self.assertIsNone(normalize_domain("no_tld"))
        self.assertIsNone(normalize_domain("http://bad.example.com/path"))
        self.assertIsNone(normalize_domain(""))

    def test_punycode_tld(self):
        self.assertEqual(normalize_domain("xn--80ak6aa92e.xn--p1ai"), "xn--80ak6aa92e.xn--p1ai")


class TestProtected(unittest.TestCase):
    def test_exact_and_www(self):
        self.assertTrue(is_protected("github.com"))
        self.assertTrue(is_protected("www.github.com"))

    def test_attacker_subdomain_not_protected(self):
        self.assertFalse(is_protected("evil.github.com"))
        self.assertFalse(is_protected("phish.blogspot.com"))


class TestParseHostsText(unittest.TestCase):
    def test_hosts_format(self):
        text = (
            "﻿# Title: Test\n"
            "! Adblock-Kommentar\n"
            "127.0.0.1 bad-one.example.com\n"
            "0.0.0.0 bad-two.example.net # Kommentar\n"
            "0.0.0.0 multi-a.example.org multi-b.example.org\n"
            "127.0.0.1 localhost\n"
            "0.0.0.0 github.com\n"
            "plain-domain.example.info\n"
        )
        self.assertEqual(parse_hosts_text(text), {
            "bad-one.example.com", "bad-two.example.net",
            "multi-a.example.org", "multi-b.example.org",
            "plain-domain.example.info",
        })


class TestParseThreatfoxCsv(unittest.TestCase):
    HEADER = ('# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type",'
              '"fk_malware","malware_alias","malware_printable","last_seen_utc",'
              '"confidence_level","reference","tags","anonymous","reporter"\n')

    def row(self, value, ioc_type, confidence):
        return (f'"2026-10-01 10:00:00", "1", "{value}", "{ioc_type}", "botnet_cc", '
                f'"win.x", "", "X", "", "{confidence}", "", "", "0", "r"\n')

    def test_only_domains_with_confidence(self):
        text = (
            "################\n# ThreatFox IOCs\n" + self.HEADER
            + self.row("c2.bad-domain.com", "domain", 100)
            + self.row("low.bad-domain.com", "domain", 25)
            + self.row("1.2.3.4:443", "ip:port", 100)
            + self.row("https://github.com/x/y", "url", 100)
            + self.row("github.com", "domain", 100)
        )
        self.assertEqual(parse_threatfox_csv(text), {"c2.bad-domain.com"})

    def test_missing_header_raises(self):
        with self.assertRaises(ValueError):
            parse_threatfox_csv('"a","b"\n')


class TestWriteDomainList(unittest.TestCase):
    def test_unchanged_content_is_not_rewritten(self):
        import tempfile
        import dns_list_mirror as mirror

        domains = {f"bad{i}.example.com" for i in range(1000)}
        with tempfile.TemporaryDirectory() as tmp:
            old_dir = mirror.OUT_DIR
            mirror.OUT_DIR = tmp
            try:
                self.assertTrue(mirror.write_domain_list(
                    "antimalware", "test.txt", "T", "S", domains, "erster Lauf"))
                path = os.path.join(tmp, "test.txt")
                with open(path, encoding="utf-8") as handle:
                    first = handle.read()
                self.assertTrue(mirror.write_domain_list(
                    "antimalware", "test.txt", "T", "S", domains, "zweiter Lauf"))
                with open(path, encoding="utf-8") as handle:
                    self.assertEqual(handle.read(), first)
            finally:
                mirror.OUT_DIR = old_dir


if __name__ == "__main__":
    unittest.main()
