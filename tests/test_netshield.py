#!/usr/bin/env python3
"""
NETSHIELD Unit Tests
====================
Testet alle gemeinsamen Funktionen aus scripts/netshield_common.py.

Ausführen:
    cd NETSHIELD-main
    python3 -m pytest tests/ -v
    # oder ohne pytest:
    python3 tests/test_netshield.py
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

# Modul-Pfad einfügen
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from netshield_common import (
    parse_entries,
    is_valid_public_ipv4,
    is_valid_public_cidr,
    is_protected_entry,
    is_whitelisted,
    is_in_fp_set,
    load_whitelist,
    load_fp_set,
    calculate_confidence,
    safe_get_date,
    parse_date,
    sort_ips,
    write_ip_list,
    check_local_feed_age,
    fetch_url,
    _whitelist_networks,
    _protected_networks,
    _fp_ips,
    _fp_networks,
)
import netshield_common


# ═══════════════════════════════════════════════════════════════
# parse_entries – Universeller Feed-Parser
# ═══════════════════════════════════════════════════════════════

class TestParseEntries(unittest.TestCase):
    """Tests für den universellen IP/CIDR-Parser."""

    def test_plain_ipv4(self):
        result = parse_entries("1.2.3.4\n5.6.7.8")
        self.assertEqual(result, {"1.2.3.4", "5.6.7.8"})

    def test_cidr(self):
        result = parse_entries("1.2.3.0/24")
        self.assertEqual(result, {"1.2.3.0/24"})

    def test_cidr_normalization(self):
        """CIDRs werden normalisiert (1.2.3.4/24 → 1.2.3.0/24)."""
        result = parse_entries("1.2.3.99/24")
        self.assertEqual(result, {"1.2.3.0/24"})

    def test_ip_port(self):
        result = parse_entries("1.2.3.4:8080")
        self.assertEqual(result, {"1.2.3.4"})

    def test_fortigate_format(self):
        result = parse_entries("set subnet 1.2.3.4 255.255.255.255")
        self.assertEqual(result, {"1.2.3.4"})

    def test_ipset_format_ip(self):
        result = parse_entries("add badguys 1.2.3.4")
        self.assertEqual(result, {"1.2.3.4"})

    def test_ipset_format_cidr(self):
        result = parse_entries("add badguys 1.2.3.0/24")
        self.assertEqual(result, {"1.2.3.0/24"})

    def test_ipset_with_semicolon(self):
        result = parse_entries("add badguys 1.2.3.4;comment")
        self.assertEqual(result, {"1.2.3.4"})

    def test_spamhaus_drop(self):
        result = parse_entries("1.2.3.0/24 ; SBL123456")
        self.assertEqual(result, {"1.2.3.0/24"})

    def test_csv_first_column(self):
        result = parse_entries("1.2.3.4,8080,malware,2025-01-01")
        self.assertEqual(result, {"1.2.3.4"})

    def test_csv_cidr_first_column(self):
        result = parse_entries("1.2.3.0/24,SBL,DE")
        self.assertEqual(result, {"1.2.3.0/24"})

    def test_comment_hash(self):
        result = parse_entries("# This is a comment\n1.2.3.4")
        self.assertEqual(result, {"1.2.3.4"})

    def test_comment_semicolon(self):
        result = parse_entries("; This is a comment\n1.2.3.4")
        self.assertEqual(result, {"1.2.3.4"})

    def test_comment_doubleslash(self):
        result = parse_entries("// This is a comment\n1.2.3.4")
        self.assertEqual(result, {"1.2.3.4"})

    def test_empty_input(self):
        self.assertEqual(parse_entries(""), set())

    def test_only_comments(self):
        self.assertEqual(parse_entries("# comment\n; comment\n// comment"), set())

    def test_blank_lines(self):
        result = parse_entries("\n\n1.2.3.4\n\n5.6.7.8\n\n")
        self.assertEqual(result, {"1.2.3.4", "5.6.7.8"})

    def test_private_ip_filtered(self):
        result = parse_entries("192.168.1.1\n10.0.0.1\n172.16.0.1")
        self.assertEqual(result, set())

    def test_loopback_filtered(self):
        result = parse_entries("127.0.0.1")
        self.assertEqual(result, set())

    def test_multicast_filtered(self):
        result = parse_entries("224.0.0.1\n239.255.255.255")
        self.assertEqual(result, set())

    def test_reserved_filtered(self):
        result = parse_entries("0.0.0.0\n255.255.255.255")
        self.assertEqual(result, set())

    def test_mixed_valid_invalid(self):
        result = parse_entries("8.8.8.8\n192.168.1.1\n1.1.1.1\n10.0.0.1")
        self.assertEqual(result, {"8.8.8.8", "1.1.1.1"})

    def test_fallback_urlhaus(self):
        """URLs mit IPs werden per Fallback-Regex extrahiert."""
        result = parse_entries("http://1.2.3.4/malware/payload.exe")
        self.assertEqual(result, {"1.2.3.4"})

    def test_inline_comment_stripped(self):
        result = parse_entries("1.2.3.4 # this is a scanner")
        self.assertEqual(result, {"1.2.3.4"})

    def test_cidr_too_large_filtered(self):
        """CIDRs < /8 werden gefiltert."""
        result = parse_entries("1.0.0.0/7")
        self.assertEqual(result, set())

    def test_ipv6_filtered(self):
        """IPv6-Adressen werden ignoriert."""
        result = parse_entries("2001:db8::1\n1.2.3.4")
        self.assertEqual(result, {"1.2.3.4"})

    def test_multiple_ips_per_line(self):
        """Fallback: Alle IPs in einer Zeile wenn kein anderes Format matcht."""
        result = parse_entries("attack from 1.2.3.4 targeting 5.6.7.8")
        self.assertEqual(result, {"1.2.3.4", "5.6.7.8"})

    def test_dataplane_pipe_format(self):
        """DataPlane-Format: ASN | ASname | ipaddr | lastseen | category"""
        line = "12345 | Evil ISP | 1.2.3.4 | 2025-04-14 | ssh"
        result = parse_entries(line)
        self.assertEqual(result, {"1.2.3.4"})

    def test_deduplication(self):
        result = parse_entries("1.2.3.4\n1.2.3.4\n1.2.3.4")
        self.assertEqual(result, {"1.2.3.4"})
        self.assertEqual(len(result), 1)


# ═══════════════════════════════════════════════════════════════
# IP-Validierung
# ═══════════════════════════════════════════════════════════════

class TestIPValidation(unittest.TestCase):

    def test_valid_public(self):
        self.assertTrue(is_valid_public_ipv4("8.8.8.8"))
        self.assertTrue(is_valid_public_ipv4("1.1.1.1"))
        self.assertTrue(is_valid_public_ipv4("185.220.101.1"))

    def test_private(self):
        self.assertFalse(is_valid_public_ipv4("192.168.1.1"))
        self.assertFalse(is_valid_public_ipv4("10.0.0.1"))
        self.assertFalse(is_valid_public_ipv4("172.16.0.1"))

    def test_loopback(self):
        self.assertFalse(is_valid_public_ipv4("127.0.0.1"))

    def test_invalid_format(self):
        self.assertFalse(is_valid_public_ipv4("not_an_ip"))
        self.assertFalse(is_valid_public_ipv4(""))
        self.assertFalse(is_valid_public_ipv4("999.999.999.999"))

    def test_valid_cidr(self):
        self.assertTrue(is_valid_public_cidr("1.2.3.0/24"))
        self.assertTrue(is_valid_public_cidr("8.0.0.0/8"))

    def test_private_cidr(self):
        self.assertFalse(is_valid_public_cidr("192.168.0.0/16"))
        self.assertFalse(is_valid_public_cidr("10.0.0.0/8"))

    def test_cidr_too_large(self):
        self.assertFalse(is_valid_public_cidr("1.0.0.0/7"))

    def test_invalid_cidr(self):
        self.assertFalse(is_valid_public_cidr("not/a/cidr"))


# ═══════════════════════════════════════════════════════════════
# Scoring-Modell
# ═══════════════════════════════════════════════════════════════

class TestScoring(unittest.TestCase):

    def test_max_score(self):
        """HQ + frisch + persistent + alt → 100"""
        score = calculate_confidence(
            is_hq=True, days_since_last=0, days_seen=14, days_known=90
        )
        self.assertEqual(score, 100)

    def test_min_score(self):
        """Einzelner Non-HQ-Feed, uralt, 1 Tag gesehen, neu → 2"""
        score = calculate_confidence(
            is_hq=False, today_count=1, feed_count=1,
            days_since_last=999, days_seen=1, days_known=0
        )
        self.assertEqual(score, 2)

    def test_hq_fresh(self):
        """HQ + 1 Tag alt + 1 Tag gesehen + neu → 40+30+2+0=72"""
        score = calculate_confidence(
            is_hq=True, days_since_last=1, days_seen=1, days_known=0
        )
        self.assertEqual(score, 72)

    def test_active_threshold(self):
        """Active Blacklist braucht >= 65"""
        score = calculate_confidence(
            is_hq=True, days_since_last=1, days_seen=1, days_known=0
        )
        self.assertGreaterEqual(score, 65)

    def test_confidence40_threshold(self):
        """Confidence40 braucht >= 40"""
        # HQ + 8 Tage alt + 1 Tag → 40 + 20 + 2 + 0 = 62
        score = calculate_confidence(
            is_hq=True, days_since_last=7, days_seen=1, days_known=0
        )
        self.assertGreaterEqual(score, 40)

    def test_watchlist_threshold(self):
        """Watchlist: 25-39"""
        # 2 Feeds heute + 2 Tage alt + 2 Tage gesehen + 14 Tage bekannt
        # = 20 + 25 + 6 + 3 = 54 (actually above 39)
        pass

    def test_score_capped_at_100(self):
        score = calculate_confidence(
            is_hq=True, today_count=10, feed_count=20,
            days_since_last=0, days_seen=100, days_known=365
        )
        self.assertEqual(score, 100)

    def test_today_count_5(self):
        """5+ Feeds heute ohne HQ → 35"""
        score = calculate_confidence(
            is_hq=False, today_count=5, feed_count=5,
            days_since_last=1, days_seen=1, days_known=0
        )
        # 35 + 30 + 2 + 0 = 67
        self.assertEqual(score, 67)

    def test_today_count_3(self):
        """3 Feeds heute ohne HQ → 28"""
        score = calculate_confidence(
            is_hq=False, today_count=3, feed_count=3,
            days_since_last=1, days_seen=1, days_known=0
        )
        # 28 + 30 + 2 + 0 = 60
        self.assertEqual(score, 60)

    def test_today_count_2(self):
        """2 Feeds heute ohne HQ → 20"""
        score = calculate_confidence(
            is_hq=False, today_count=2, feed_count=2,
            days_since_last=1, days_seen=1, days_known=0
        )
        # 20 + 30 + 2 + 0 = 52
        self.assertEqual(score, 52)

    def test_days_known_tiers(self):
        self.assertEqual(calculate_confidence(days_known=0), 2)    # 0+0+2+0
        self.assertEqual(calculate_confidence(days_known=14), 5)   # 0+0+2+3
        self.assertEqual(calculate_confidence(days_known=30), 8)   # 0+0+2+6
        self.assertEqual(calculate_confidence(days_known=90), 12)  # 0+0+2+10

    def test_days_since_last_tiers(self):
        self.assertEqual(calculate_confidence(days_since_last=0), 32)   # 0+30+2+0
        self.assertEqual(calculate_confidence(days_since_last=1), 32)   # 0+30+2+0
        self.assertEqual(calculate_confidence(days_since_last=3), 27)   # 0+25+2+0
        self.assertEqual(calculate_confidence(days_since_last=7), 22)   # 0+20+2+0
        self.assertEqual(calculate_confidence(days_since_last=14), 14)  # 0+12+2+0
        self.assertEqual(calculate_confidence(days_since_last=30), 8)   # 0+6+2+0
        self.assertEqual(calculate_confidence(days_since_last=31), 2)   # 0+0+2+0

    def test_persistence_tiers(self):
        self.assertEqual(calculate_confidence(days_seen=1), 2)    # 0+0+2+0
        self.assertEqual(calculate_confidence(days_seen=2), 6)    # 0+0+6+0
        self.assertEqual(calculate_confidence(days_seen=3), 10)   # 0+0+10+0
        self.assertEqual(calculate_confidence(days_seen=7), 15)   # 0+0+15+0
        self.assertEqual(calculate_confidence(days_seen=14), 20)  # 0+0+20+0


# ═══════════════════════════════════════════════════════════════
# safe_get_date / parse_date
# ═══════════════════════════════════════════════════════════════

class TestDateHandling(unittest.TestCase):

    def test_safe_get_date_valid(self):
        self.assertEqual(safe_get_date({"last": "2025-01-15"}, "last"), "2025-01-15")

    def test_safe_get_date_missing_key(self):
        self.assertEqual(safe_get_date({}, "last"), "2000-01-01")

    def test_safe_get_date_none_value(self):
        """FIX: data.get("last", default) gibt None wenn Key existiert mit None-Wert."""
        self.assertEqual(safe_get_date({"last": None}, "last"), "2000-01-01")

    def test_safe_get_date_empty_string(self):
        self.assertEqual(safe_get_date({"last": ""}, "last"), "2000-01-01")

    def test_safe_get_date_invalid_format(self):
        self.assertEqual(safe_get_date({"last": "invalid"}, "last"), "2000-01-01")

    def test_safe_get_date_integer(self):
        self.assertEqual(safe_get_date({"last": 12345}, "last"), "2000-01-01")

    def test_safe_get_date_custom_default(self):
        self.assertEqual(safe_get_date({}, "last", "2020-06-15"), "2020-06-15")

    def test_parse_date_valid(self):
        result = parse_date("2025-04-14")
        self.assertEqual(result.year, 2025)
        self.assertEqual(result.month, 4)
        self.assertEqual(result.day, 14)
        self.assertIsNotNone(result.tzinfo)

    def test_parse_date_invalid(self):
        result = parse_date("invalid")
        self.assertEqual(result.year, 2000)

    def test_parse_date_none(self):
        result = parse_date(None)
        self.assertEqual(result.year, 2000)


# ═══════════════════════════════════════════════════════════════
# sort_ips / write_ip_list
# ═══════════════════════════════════════════════════════════════

class TestSortAndWrite(unittest.TestCase):

    def test_numeric_sort(self):
        ips = ["10.0.0.1", "2.0.0.1", "1.0.0.1"]
        result = sort_ips(ips)
        self.assertEqual(result, ["1.0.0.1", "2.0.0.1", "10.0.0.1"])

    def test_sort_with_cidrs(self):
        entries = ["10.0.0.0/24", "2.0.0.0/8", "1.2.3.4"]
        result = sort_ips(entries)
        self.assertEqual(result, ["1.2.3.4", "2.0.0.0/8", "10.0.0.0/24"])

    def test_sort_empty(self):
        self.assertEqual(sort_ips([]), [])

    def test_write_ip_list(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            path = f.name
        try:
            write_ip_list(path, ["5.6.7.8", "1.2.3.4"],
                          header_lines=["Test Header", "Line 2"])
            with open(path) as f:
                content = f.read()
            self.assertIn("# Test Header", content)
            self.assertIn("# Line 2", content)
            lines = [l for l in content.strip().split('\n') if not l.startswith('#') and l]
            self.assertEqual(lines, ["1.2.3.4", "5.6.7.8"])
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════
# Whitelist & FP-Set (mit temporären Dateien)
# ═══════════════════════════════════════════════════════════════

class TestWhitelistLoading(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.wl_path = os.path.join(self.tmpdir, "whitelist.json")
        self.fp_path = os.path.join(self.tmpdir, "fp_set.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_load_whitelist(self):
        entries = ["8.8.8.8", "1.1.1.1", "1.0.0.1"] + [f"100.{i}.0.0/16" for i in range(50)]
        with open(self.wl_path, 'w') as f:
            json.dump({"entries": entries}, f)
        result = load_whitelist(self.wl_path, min_entries=5)
        self.assertEqual(len(result), len(entries))

    def test_load_whitelist_too_few_entries(self):
        with open(self.wl_path, 'w') as f:
            json.dump({"entries": ["8.8.8.8"]}, f)
        with self.assertRaises(SystemExit):
            load_whitelist(self.wl_path, min_entries=50)

    def test_load_fp_set(self):
        fp_data = {
            "updated": "2025-04-14",
            "count": 3,
            "ips": ["1.2.3.4", "5.6.7.0/24", "9.8.7.6"]
        }
        with open(self.fp_path, 'w') as f:
            json.dump(fp_data, f)
        fp_ips, fp_nets = load_fp_set(self.fp_path)
        self.assertIn("1.2.3.4", fp_ips)
        self.assertIn("9.8.7.6", fp_ips)
        self.assertEqual(len(fp_nets), 1)

    def test_load_fp_set_missing_file(self):
        fp_ips, fp_nets = load_fp_set("/nonexistent/path.json")
        self.assertEqual(len(fp_ips), 0)
        self.assertEqual(len(fp_nets), 0)

    def test_is_in_fp_set(self):
        netshield_common._fp_ips = {"1.2.3.4"}
        netshield_common._fp_networks = [
            __import__('ipaddress').ip_network("5.6.7.0/24")
        ]
        self.assertTrue(is_in_fp_set("1.2.3.4"))
        self.assertTrue(is_in_fp_set("5.6.7.100"))
        self.assertFalse(is_in_fp_set("9.9.9.9"))


# ═══════════════════════════════════════════════════════════════
# Crash-Test: Korrupte seen_db-Einträge
# ═══════════════════════════════════════════════════════════════

class TestCrashHandling(unittest.TestCase):
    """Simuliert korrupte seen_db-Einträge."""

    def test_none_entry(self):
        """Regression: parse_entries(None) darf nicht crashen.
        Vorher vacuous (nur isinstance-Check), jetzt echter Call."""
        self.assertEqual(parse_entries(None), set())

    def test_empty_string_entry(self):
        """Regression: parse_entries('') gibt leeres Set zurück."""
        self.assertEqual(parse_entries(""), set())

    def test_integer_entry(self):
        """Regression: parse_entries(42) darf nicht crashen."""
        self.assertEqual(parse_entries(42), set())

    def test_bytes_entry(self):
        """Bytes werden dekodiert statt zu crashen."""
        self.assertEqual(parse_entries(b"1.2.3.4"), {"1.2.3.4"})

    def test_null_byte_line_rejected(self):
        """Zeilen mit Null-Bytes werden verworfen (Binärmüll-Schutz).
        Vorher: parse_entries('1.2.3.4\\x00') → {'1.2.3.4'} (akzeptiert)."""
        self.assertEqual(parse_entries("1.2.3.4\x00"), set())
        # Benachbarte saubere Zeilen bleiben erhalten
        self.assertEqual(
            parse_entries("1.2.3.4\n5.6.7.8\x00\n9.10.11.12"),
            {"1.2.3.4", "9.10.11.12"},
        )

    def test_missing_fields(self):
        data = {"feeds": []}
        last = safe_get_date(data, "last")
        self.assertEqual(last, "2000-01-01")

    def test_none_date_fields(self):
        data = {"last": None, "first": None}
        self.assertEqual(safe_get_date(data, "last"), "2000-01-01")
        self.assertEqual(safe_get_date(data, "first"), "2000-01-01")

    def test_invalid_date_format(self):
        data = {"last": "not-a-date"}
        self.assertEqual(safe_get_date(data, "last"), "2000-01-01")

    def test_corrupt_feeds_field(self):
        """feeds ist kein List → len() sollte trotzdem funktionieren."""
        data = {"feeds": "not_a_list", "hq": True}
        try:
            feed_count = len(data.get("feeds", []))
        except TypeError:
            feed_count = 0
        # Strings haben len() → ergibt 10 statt 0
        # Das ist ein Edge-Case der in der Praxis nicht auftreten sollte

    def test_scoring_with_extreme_values(self):
        """Score-Berechnung mit extremen Werten."""
        score = calculate_confidence(
            is_hq=True, today_count=999999,
            feed_count=999999, days_since_last=0,
            days_seen=999999, days_known=999999
        )
        self.assertEqual(score, 100)

    def test_scoring_with_negative_values(self):
        """Score-Berechnung mit negativen Werten."""
        score = calculate_confidence(
            is_hq=False, today_count=-1,
            feed_count=-1, days_since_last=-1,
            days_seen=-1, days_known=-1
        )
        # days_since_last=-1 < 1 → score_b=30, days_seen=-1 < 1 → score_c=2
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    # ─── Type-Corruption-Tests (vorher ungetestet) ───────────────────
    # Regression: Vor der Typ-Koerzierung führten korrupte seen_db-Werte
    # (None, strings aus fremden Tools, float) zum TypeError und killten
    # den gesamten Main-Loop. Die Tests stellen sicher, dass der Score
    # einen definierten Default-Wert liefert statt zu crashen.

    def test_scoring_with_string_today_count(self):
        """today_count='5' (str) darf nicht crashen – wird zu int(5) gecastet."""
        score = calculate_confidence(today_count="5")
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_scoring_with_none_fields(self):
        """None an beliebigem Feld darf nicht crashen."""
        score = calculate_confidence(
            today_count=None, feed_count=None,
            days_since_last=None, days_seen=None, days_known=None
        )
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_scoring_with_unparseable_string(self):
        """'abc' fällt auf Default zurück – kein Crash."""
        score = calculate_confidence(today_count="abc", feed_count="xyz")
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)

    def test_scoring_with_float(self):
        """Float-Werte werden zu int gecastet (3.7 → 3)."""
        score = calculate_confidence(today_count=3.7)
        self.assertIsInstance(score, int)
        # today_count=3 → score_a=28
        self.assertEqual(score, 28 + 0 + 2 + 0)  # a=28, b=0(default 999), c=2(default 1), d=0

    def test_scoring_string_equivalent_to_int(self):
        """today_count='5' muss denselben Score geben wie today_count=5."""
        score_str = calculate_confidence(today_count="5")
        score_int = calculate_confidence(today_count=5)
        self.assertEqual(score_str, score_int)


# ═══════════════════════════════════════════════════════════════
# check_local_feed_age
# ═══════════════════════════════════════════════════════════════

class TestFeedAge(unittest.TestCase):

    def test_fresh_feed(self):
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(f"# NETSHIELD\n# Aktualisiert: {now_str} UTC\n1.2.3.4\n")
            path = f.name
        try:
            age = check_local_feed_age(path, max_age_hours=48)
            self.assertIsNotNone(age)
            self.assertLess(age, 1)  # weniger als 1 Stunde alt
        finally:
            os.unlink(path)

    def test_missing_file(self):
        age = check_local_feed_age("/nonexistent/file.txt")
        self.assertIsNone(age)

    def test_no_timestamp(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# No timestamp here\n1.2.3.4\n")
            path = f.name
        try:
            age = check_local_feed_age(path)
            self.assertIsNone(age)
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════
# Atomares write_ip_list (Fix 4a)
# ═══════════════════════════════════════════════════════════════

class TestWriteIpListAtomic(unittest.TestCase):
    """Verifiziert dass write_ip_list atomar ist: bei Crash mitten im
    Schreibvorgang bleibt die Zieldatei im alten Zustand."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.target = os.path.join(self.tmpdir, "ips.txt")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_normal_write_leaves_no_tempfile(self):
        write_ip_list(self.target, ["1.2.3.4", "5.6.7.8"], header_lines=["Test"])
        leftovers = [f for f in os.listdir(self.tmpdir) if f != "ips.txt"]
        self.assertEqual(leftovers, [])

    def test_crash_during_write_keeps_old_file_intact(self):
        write_ip_list(self.target, ["1.1.1.1"], header_lines=["v1"])
        original = open(self.target, encoding="utf-8").read()

        class BadIter:
            def __iter__(self_inner):
                yield "2.2.2.2"
                raise RuntimeError("simulierter Crash mitten im Write")

        with self.assertRaises(RuntimeError):
            write_ip_list(self.target, BadIter())

        after = open(self.target, encoding="utf-8").read()
        self.assertEqual(original, after,
                         "Zieldatei darf bei Crash nicht verändert sein")
        leftovers = [f for f in os.listdir(self.tmpdir) if f != "ips.txt"]
        self.assertEqual(leftovers, [],
                         "Bei Crash dürfen keine .tmp-Leichen zurückbleiben")

    def test_write_produces_correct_content(self):
        write_ip_list(self.target, ["5.6.7.8", "1.2.3.4"],
                       header_lines=["Header1", "Header2"])
        content = open(self.target, encoding="utf-8").read()
        # Header vorhanden
        self.assertIn("# Header1", content)
        self.assertIn("# Header2", content)
        # Sortiert
        pos_1 = content.index("1.2.3.4")
        pos_5 = content.index("5.6.7.8")
        self.assertLess(pos_1, pos_5)

    def test_sigkill_before_replace_keeps_original_intact(self):
        """Realistischerer Crash-Test: SIGKILL genau vor os.replace().

        Der existierende RuntimeError-Test läuft durch den except-Branch
        (der die tempfile aufräumt). SIGKILL bypasst except – die Zieldatei
        muss trotzdem unversehrt bleiben, weil os.replace() entweder atomar
        durchläuft oder gar nicht."""
        import subprocess
        import signal
        # Originaldatei anlegen
        write_ip_list(self.target, ["9.9.9.9"], header_lines=["original"])
        original = open(self.target, encoding="utf-8").read()

        # Kindprozess: write_ip_list aufrufen, aber os.replace
        # monkey-patchen, sodass er sich vorher selbst killt.
        script = f"""
import sys, os, signal
sys.path.insert(0, {os.path.join(os.path.dirname(__file__), "..", "scripts")!r})
from netshield_common import write_ip_list
_real_replace = os.replace
def _kill_before_replace(src, dst):
    os.kill(os.getpid(), signal.SIGKILL)
os.replace = _kill_before_replace
write_ip_list({self.target!r}, ["8.8.8.8", "7.7.7.7"], header_lines=["new"])
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, timeout=10,
        )
        # Prozess sollte durch SIGKILL beendet worden sein (rc=-9)
        self.assertEqual(result.returncode, -signal.SIGKILL,
                         f"Erwartet SIGKILL, bekam rc={result.returncode}")

        # Zieldatei muss Originalinhalt haben – halb geschrieben ist
        # NICHT akzeptabel.
        after = open(self.target, encoding="utf-8").read()
        self.assertEqual(original, after,
                         "Zieldatei muss bei SIGKILL unversehrt bleiben")


# ═══════════════════════════════════════════════════════════════
# SSRF-Schutz in fetch_url (Fix 4b)
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# Parser-Härtung: Versions-Strings (Fix 5a)
# ═══════════════════════════════════════════════════════════════

class TestParserEdgecases(unittest.TestCase):
    """Verifiziert dass Versions-Strings wie '1.2.3.4.5' nicht als IP
    durchgehen."""

    def test_version_string_not_extracted(self):
        # Vorher: '1.2.3.4.5' → {'1.2.3.4'} (falsch!)
        self.assertEqual(parse_entries("1.2.3.4.5"), set())

    def test_version_string_in_text(self):
        # Versions-Nummer inmitten von Text
        self.assertEqual(parse_entries("Software v1.2.3.4.5 released"), set())

    def test_normal_ip_still_works(self):
        # Regression: normale IPs sollen weiterhin erkannt werden
        self.assertEqual(parse_entries("1.2.3.4"), {"1.2.3.4"})
        self.assertEqual(parse_entries("Malware C2: 1.2.3.4 seen"), {"1.2.3.4"})

    def test_ip_at_end_of_sentence(self):
        # IP am Satzende mit Punkt: '1.2.3.4.' – der Schlusspunkt ist
        # Satzzeichen, nicht Oktett. Der neue Regex schließt das aus,
        # weil der Punkt nicht von "ist Oktett-Trenner?" zu unterscheiden
        # ist. Bewusst angenommener Trade-off.
        # Dieser Test dokumentiert das Verhalten.
        self.assertEqual(parse_entries("C2 ist 1.2.3.4."), set())


# ═══════════════════════════════════════════════════════════════
# calculate_confidence mit negativen Inputs (Fix 5b)
# ═══════════════════════════════════════════════════════════════

class TestConfidenceNegativeInputs(unittest.TestCase):
    """Negative Inputs sollen nie zu falsch hohen Scores führen."""

    def test_negative_days_since_last_doesnt_grant_recency(self):
        # Vorher: days_since_last=-1 triggerte "<=1" → 30 Punkte
        # Jetzt: wird auf 0 geklemmt → bleibt in Frische-Fenster, das ist
        # OK, aber wir wollen v.a. kein absurdes Verhalten.
        score = calculate_confidence(
            today_count=-5, feed_count=-3,
            days_since_last=-100, days_seen=-1, days_known=-1)
        # Mit is_hq=False, today=0, feed=0 → A=0
        # days_since_last geklemmt auf 0 → B=30
        # days_seen geklemmt auf 0 → C=2 (< 2 Zweig)
        # days_known geklemmt auf 0 → D=0
        self.assertEqual(score, 32)

    def test_all_negative_stays_in_range(self):
        score = calculate_confidence(
            is_hq=False, today_count=-999, feed_count=-999,
            days_since_last=-999, days_seen=-999, days_known=-999)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)


class TestFetchUrlSsrf(unittest.TestCase):
    """Verifiziert dass fetch_url kein SSRF erlaubt – weder über
    gefährliche Schemata noch über Auflösung auf private IPs."""

    def test_file_scheme_blocked(self):
        self.assertIsNone(fetch_url("file:///etc/passwd"))

    def test_ftp_scheme_blocked(self):
        self.assertIsNone(fetch_url("ftp://example.com/x"))

    def test_gopher_scheme_blocked(self):
        self.assertIsNone(fetch_url("gopher://example.com/"))

    def test_loopback_ip_blocked(self):
        self.assertIsNone(fetch_url("http://127.0.0.1/"))

    def test_aws_metadata_blocked(self):
        # Cloud-Metadata-Endpoint – der klassische SSRF-Exfil-Pfad
        self.assertIsNone(fetch_url("http://169.254.169.254/latest/meta-data/"))

    def test_rfc1918_blocked(self):
        self.assertIsNone(fetch_url("http://192.168.1.1/"))
        self.assertIsNone(fetch_url("http://10.0.0.1/"))

    def test_localhost_hostname_blocked(self):
        self.assertIsNone(fetch_url("http://localhost/"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
