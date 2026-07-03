#!/usr/bin/env python3
"""
NETSHIELD Feed-Parser Tests
===========================
Regressionstests fuer den zentralen, formatbewussten Feed-Parser
``parse_feed_entries()`` aus scripts/netshield_common.py.

Diese Funktion ist seit dem Umbau "Zentraler Feed-Parser" die gemeinsame
Parser-API fuer Auto-Discovery (auto_feed_discovery.yml, ueber den
extract_ips()-Wrapper) und den Combined-Workflow
(update_combined_blacklist.yml). Beide Workflows haengen davon ab, dass
ein Feed bei der Entdeckung und bei der Aufnahme nach exakt denselben
Regeln ausgewertet wird.

Die uebrige Testsuite (test_netshield.py) deckt die Bausteine ab
(parse_entries, is_valid_public_ipv4, is_protected_entry,
calculate_confidence). Diese Datei schliesst die Luecke fuer die
Format-Erkennung von parse_feed_entries selbst.

Ausfuehren:
    cd NETSHIELD-main
    python3 -m pytest tests/test_feed_parser.py -v
    # oder ohne pytest:
    python3 tests/test_feed_parser.py

Hinweis zu den Test-IPs: Es werden ausschliesslich global routbare,
nicht-reservierte IPv4-Adressen verwendet. RFC-5737-Dokumentations-
bereiche (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) werden vom
Parser korrekt als nicht-oeffentlich abgelehnt und eignen sich daher
NICHT als positive Testdaten.
"""

import os
import sys
import unittest

# Modul-Pfad einfuegen (identisch zu test_netshield.py)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import netshield_common
from netshield_common import parse_feed_entries


# ═══════════════════════════════════════════════════════════════
# Grundlegende Ein-/Ausgabe und Sicherheits-Policy
# ═══════════════════════════════════════════════════════════════

class TestFeedParserCore(unittest.TestCase):
    """Robustheit und die konservative NETSHIELD-Sicherheits-Policy."""

    def test_plain_ip_list(self):
        result = parse_feed_entries("45.83.12.7\n91.219.29.8\n# comment\n")
        self.assertEqual(result, {"45.83.12.7", "91.219.29.8"})

    def test_slash32_normalized_to_host(self):
        # /32 wird zur reinen Host-IP normalisiert (kein "/32"-Suffix).
        result = parse_feed_entries("185.220.101.5/32\n")
        self.assertEqual(result, {"185.220.101.5"})

    def test_wide_cidr_not_expanded(self):
        # Breitere Netze werden NICHT in Einzel-IPs expandiert.
        self.assertEqual(parse_feed_entries("5.188.10.0/24\n"), set())

    def test_ip_range_dash_dropped(self):
        # Ranges werden komplett verworfen (nicht nur Start/Ende).
        self.assertEqual(parse_feed_entries("46.161.40.30-46.161.40.50\n"), set())

    def test_ip_range_dots_dropped(self):
        self.assertEqual(parse_feed_entries("46.161.40.30..46.161.40.50\n"), set())

    def test_private_and_reserved_rejected(self):
        result = parse_feed_entries("192.168.1.1\n10.0.0.5\n127.0.0.1\n")
        self.assertEqual(result, set())

    def test_documentation_range_rejected(self):
        # RFC 5737 TEST-NET ist nicht oeffentlich.
        self.assertEqual(parse_feed_entries("203.0.113.5\n198.51.100.9\n"), set())

    def test_null_bytes_reject_whole_input(self):
        # Binaerdaten mit Null-Byte werden komplett verworfen.
        self.assertEqual(parse_feed_entries("45.83.12.7\x00garbage"), set())

    def test_empty_and_whitespace(self):
        self.assertEqual(parse_feed_entries("   \n\n"), set())
        self.assertEqual(parse_feed_entries(""), set())

    def test_none_input(self):
        self.assertEqual(parse_feed_entries(None), set())

    def test_bytes_input_decoded(self):
        result = parse_feed_entries(b"45.83.12.7\n91.219.29.8\n")
        self.assertEqual(result, {"45.83.12.7", "91.219.29.8"})


# ═══════════════════════════════════════════════════════════════
# Strukturierte Formate: JSON / JSONL / XML / CSV
# ═══════════════════════════════════════════════════════════════

class TestFeedParserStructured(unittest.TestCase):
    """JSON, JSONL, XML und CSV inkl. Metadaten-/Spaltenfilter."""

    def test_json_extracts_ip_skips_reporter(self):
        text = '{"indicators":[{"ip":"193.169.53.1"},{"reporter":"89.248.165.2"}]}'
        # reporter-Feld ist Metadaten und wird uebersprungen.
        self.assertEqual(parse_feed_entries(text), {"193.169.53.1"})

    def test_jsonl_multiple_rows(self):
        text = '{"ip":"194.26.29.3"}\n{"ip":"141.98.10.4"}\n'
        self.assertEqual(parse_feed_entries(text), {"194.26.29.3", "141.98.10.4"})

    def test_xml_extracts_ip_skips_gateway(self):
        text = ("<root><entry><ip>80.82.77.5</ip></entry>"
                "<gateway>23.129.64.6</gateway></root>")
        self.assertEqual(parse_feed_entries(text), {"80.82.77.5"})

    def test_csv_picks_ioc_column_not_reporter(self):
        text = ("ioc_ip,reporter_ip\n"
                "171.25.193.8,89.248.165.2\n"
                "209.141.55.10,89.248.165.2\n")
        # Nur die wahrscheinlichste IP-Spalte (ioc_ip) wird uebernommen.
        self.assertEqual(parse_feed_entries(text), {"171.25.193.8", "209.141.55.10"})


# ═══════════════════════════════════════════════════════════════
# Firewall- / Router- / Proxy-Syntaxen
# ═══════════════════════════════════════════════════════════════

class TestFeedParserFirewall(unittest.TestCase):
    """Firewall- und Router-Formate; Allow-Regeln duerfen nicht blocken."""

    def test_nftables_elements_set(self):
        text = ('table ip filter { set b { type ipv4_addr; '
                'elements = { 45.83.12.7, 91.219.29.8 } } }')
        self.assertEqual(parse_feed_entries(text), {"45.83.12.7", "91.219.29.8"})

    def test_ipset_add(self):
        text = "add myset 185.220.101.5\nadd myset 5.188.10.20\n"
        self.assertEqual(parse_feed_entries(text), {"185.220.101.5", "5.188.10.20"})

    def test_mikrotik_address_list(self):
        text = "/ip firewall address-list add address=46.161.40.30 list=block"
        self.assertEqual(parse_feed_entries(text), {"46.161.40.30"})

    def test_iptables_drop_source_accept_ignored(self):
        text = ("-A INPUT -s 193.169.53.1 -j DROP\n"
                "-A INPUT -s 45.83.12.7 -j ACCEPT\n")
        # ACCEPT-Regel wird ignoriert.
        self.assertEqual(parse_feed_entries(text), {"193.169.53.1"})

    def test_cisco_deny_host_permit_ignored(self):
        text = ("access-list 100 deny ip host 89.248.165.2 any\n"
                "access-list 100 permit ip host 45.83.12.7 any")
        self.assertEqual(parse_feed_entries(text), {"89.248.165.2"})

    def test_fortigate_host_mask_only(self):
        text = ("config firewall address\n"
                "set subnet 194.26.29.3 255.255.255.255\n"
                "set subnet 5.188.10.0 255.255.255.0")
        # Nur die /32-Hostmaske; das /24-Subnetz wird abgelehnt.
        self.assertEqual(parse_feed_entries(text), {"194.26.29.3"})

    def test_pf_block_from(self):
        text = "block in from 141.98.10.4 to any\n"
        self.assertEqual(parse_feed_entries(text), {"141.98.10.4"})

    def test_nginx_deny_allow_ignored(self):
        text = "deny 80.82.77.5;\nallow 45.83.12.7;\n"
        self.assertEqual(parse_feed_entries(text), {"80.82.77.5"})

    def test_suricata_drop_source_alert_ignored(self):
        text = ('drop ip 23.129.64.6 any -> $HOME_NET any (msg:"x";)\n'
                'alert ip 45.83.12.7 any -> any any (msg:"y";)')
        self.assertEqual(parse_feed_entries(text), {"23.129.64.6"})

    def test_clash_ip_and_ip_cidr32(self):
        text = "IP-CIDR,171.25.193.8/32,REJECT\nIP,209.141.55.10,REJECT\n"
        self.assertEqual(parse_feed_entries(text), {"171.25.193.8", "209.141.55.10"})

    def test_allowlist_not_treated_as_block(self):
        # ignoreip ist eine Allow-Regel und darf nichts blocken.
        self.assertEqual(parse_feed_entries("ignoreip = 45.83.12.7\n"), set())


# ═══════════════════════════════════════════════════════════════
# Key-Value (YAML/TOML/INI)
# ═══════════════════════════════════════════════════════════════

class TestFeedParserKeyValue(unittest.TestCase):
    def test_yaml_block_key_extracted_gateway_skipped(self):
        text = "block_ip: 193.169.53.1\ngateway: 89.248.165.2\n"
        self.assertEqual(parse_feed_entries(text), {"193.169.53.1"})


# ═══════════════════════════════════════════════════════════════
# source_hint: Format-Hinweis, Query/Fragment-Strip, .gz-Innenendung
# ═══════════════════════════════════════════════════════════════

class TestFeedParserSourceHint(unittest.TestCase):
    def test_json_hint_with_query_and_fragment(self):
        # Fuehrende Leerzeile -> beginnt nicht mit "{"; Endung .json (nach
        # Entfernen von ?query und #fragment) liefert den Format-Hinweis.
        text = '\n{"ip":"193.169.53.1"}\n'
        result = parse_feed_entries(
            text, source_hint="https://host/path/feed.json?token=1#frag")
        self.assertEqual(result, {"193.169.53.1"})

    def test_gz_inner_extension_treated_as_csv(self):
        text = "ioc_ip,reporter_ip\n171.25.193.8,89.248.165.2\n"
        result = parse_feed_entries(
            text, source_hint="https://host/list.csv.gz")
        # .gz wird als bereits entpackte Huelle behandelt -> csv-Hinweis.
        self.assertEqual(result, {"171.25.193.8"})


# ═══════════════════════════════════════════════════════════════
# Pipeline-Modus (use_protected_check=True, Combined-Workflow)
# ═══════════════════════════════════════════════════════════════

class TestFeedParserProtectedMode(unittest.TestCase):
    """Combined nutzt use_protected_check=True. Das setzt eine geladene
    Whitelist voraus (sonst WhitelistNotLoadedError) und entfernt
    zusaetzlich geschuetzte / auf der Whitelist stehende Eintraege."""

    def setUp(self):
        netshield_common._reset_whitelist_for_testing()
        netshield_common.load_whitelist(min_entries=5)

    def tearDown(self):
        netshield_common._reset_whitelist_for_testing()

    def test_protected_filters_whitelist_and_private(self):
        # 1.0.0.1 und 8.8.8.8 stehen in whitelist.json -> raus.
        # 192.168.1.1 ist privat -> raus. 5.5.5.5 / 11.22.33.44 bleiben.
        text = "1.0.0.1\n8.8.8.8\n5.5.5.5\n11.22.33.44\n192.168.1.1\n"
        result = parse_feed_entries(text, use_protected_check=True)
        self.assertNotIn("1.0.0.1", result)
        self.assertNotIn("8.8.8.8", result)
        self.assertNotIn("192.168.1.1", result)
        self.assertIn("5.5.5.5", result)
        self.assertIn("11.22.33.44", result)

    def test_protected_requires_loaded_whitelist(self):
        # Ohne geladene Whitelist muss der Pipeline-Modus fail-closed raisen.
        netshield_common._reset_whitelist_for_testing()
        with self.assertRaises(netshield_common.WhitelistNotLoadedError):
            parse_feed_entries("5.5.5.5\n", use_protected_check=True)


# ═══════════════════════════════════════════════════════════════
# Konsistenz Discovery <-> Combined
# ═══════════════════════════════════════════════════════════════

class TestFeedParserConsistency(unittest.TestCase):
    """Kernziel des Umbaus: dieselbe Extraktion in beiden Workflows.

    Der Discovery-Wrapper ruft parse_feed_entries(use_protected_check=
    False) auf; Combined ruft es mit use_protected_check=True auf. Bei
    Feeds ohne Whitelist-/Private-Treffer muessen beide identisch sein.
    """

    def setUp(self):
        netshield_common._reset_whitelist_for_testing()
        netshield_common.load_whitelist(min_entries=5)

    def tearDown(self):
        netshield_common._reset_whitelist_for_testing()

    def test_same_extraction_both_modes(self):
        text = ('table ip f { set b { type ipv4_addr; '
                'elements = { 45.83.12.7, 91.219.29.8 } } }')
        discovery = parse_feed_entries(text, use_protected_check=False)
        combined = parse_feed_entries(text, use_protected_check=True)
        self.assertEqual(discovery, combined)
        self.assertEqual(discovery, {"45.83.12.7", "91.219.29.8"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
