
# NETSHIELD Patch: FIX BUG-CGNAT1 + FIX BUG-PRIV2

## Was wurde behoben?

### Bug #1 – FIX BUG-CGNAT1: CGNAT-Einzel-IPs passierten `is_valid_public_ipv4()`

**Vorher:**
```python
>>> is_valid_public_ipv4("100.64.0.1")
True   # falsch — RFC 6598 CGNAT, nie öffentlich routbar
```

**Grund:** Python-stdlib `ipaddress.ip_address("100.64.0.1").is_private` liefert
`False`, weil CGNAT (Carrier-Grade NAT) erst seit RFC 6598 (2012) definiert ist
und stdlib dies nicht abdeckt.

**Auswirkung:** Einzelne CGNAT-IPs aus naiv-konfigurierten Upstream-Feeds (z.B.
Honeypot in einem Mobilfunknetz) konnten auf die Blacklist gelangen und so
**legitime ISP-Kunden blockieren**, weil CGNAT-Ranges pro Provider isoliert sind.

**Fix:** `is_valid_public_ipv4()` prüft zusätzlich gegen die explizite
`_RESERVED_NETS`-Liste, die CGNAT enthält. Bringt die Funktion in Deckung mit
`is_valid_public_cidr()`, das diesen Check seit `FIX BUG-PRIV1` schon hat.

---

### Bug #2 – FIX BUG-PRIV2: `is_protected_entry()` ließ `169.0.0.0/8` durch

**Vorher:**
```python
>>> is_valid_public_cidr("169.0.0.0/8")
False    # richtig: /8 deckt 169.254/16 link-local ab
>>> is_protected_entry("169.0.0.0/8")
False    # FALSCH — sollte True sein
>>> parse_entries("169.0.0.0/8", use_protected_check=True)
{'169.0.0.0/8'}    # → Bug: /8 könnte auf die Blacklist
```

**Grund:** Es gab **zwei Listen** reservierter Bereiche:
- `_RFC_PRIVATE_NETS` (3 Einträge, nur RFC1918) → genutzt von `is_protected_entry`
- `_PRIVATE_RANGES` (7 Einträge, voll)          → genutzt von `is_valid_public_cidr`

Divergenz zwischen zwei Funktionen mit gleichem Vertrag.

**Auswirkung:** Ein `/8`-CIDR, der überlappende reservierte Ranges (Loopback,
Link-Local, CGNAT, Multicast) nur teilweise enthält, konnte via
`parse_entries(use_protected_check=True)` auf die Blacklist geraten. In der
Praxis unwahrscheinlich (kein seriöser Threat-Feed publiziert /8s), aber eine
echte Konsistenz-Lücke.

**Fix:** Eine einzige `_RESERVED_NETS`-Liste als Single Source of Truth.
`_RFC_PRIVATE_NETS` und `_PRIVATE_RANGES` bleiben als Backward-Compat-Aliase
erhalten.

---

## Geänderte Dateien

| Datei | Änderung |
|---|---|
| `scripts/netshield_common.py` | +30/-5 Zeilen (Netze-Liste unifiziert, beide Funktionen gepatcht) |
| `tests/test_netshield.py` | +125/-1 Zeilen (13 neue Regression-Tests) |

## Tests

```
────────────────────────────────────
pytest tests/                      → 155 passed
  (vorher 142; +13 neue Tests)

check_security_hygiene.py          → Alle 6 Kategorien PASS

Edge-case suite (75 cases)         → 0 mismatches
Crash-test (29 poisoned entries)   → 0 unhandled crashes
────────────────────────────────────
```

### Neue Tests

**`TestBugCgnat1Regression` (7 Tests)**
- `test_cgnat_start_rejected` — `100.64.0.0` abgelehnt
- `test_cgnat_middle_rejected` — `100.100.100.100` abgelehnt
- `test_cgnat_end_rejected` — `100.127.255.255` abgelehnt
- `test_just_before_cgnat_accepted` — `100.63.255.255` akzeptiert
- `test_just_after_cgnat_accepted` — `100.128.0.0` akzeptiert
- `test_ivp4_still_rejects_rfc1918` — keine Regression
- `test_public_ips_still_pass` — `8.8.8.8`, `1.1.1.1`, etc. funktionieren
- `test_parse_entries_filters_cgnat_ips` — end-to-end durch `parse_entries`

**`TestBugPriv2Regression` (5 Tests)**
- `test_169_slash_8_rejected` — Hauptfall
- `test_100_slash_9_rejected_via_protected` — CGNAT-Overlap
- `test_parse_entries_rejects_reserved_supernets` — 6 Overlap-Ranges
- `test_adjacent_cidrs_still_accepted` — keine Overcorrection
- `test_reserved_nets_is_single_source` — Alias-Invariante

---

## Performance-Impact

- `is_valid_public_ipv4`: ~3µs → ~6µs pro Call (100k Calls: 0.3s → 0.6s)
- `is_protected_entry`: ~16µs → ~44µs pro Call (dominant durch Whitelist-
  Overlap-Loop, nicht durch den neuen Check)

Für den `update_combined_blacklist`-Workflow (~500k IPs/Lauf) ergibt das
**ca. 1-2% zusätzliche Gesamtlaufzeit** — unkritisch bei 15-30min typischer
Laufzeit und 90min Timeout. Korrektheit > Performance in diesem Codepfad.

---

## Breaking Changes

**Keine.** Die öffentliche API (alle exported functions) bleibt identisch.
`_RFC_PRIVATE_NETS` und `_PRIVATE_RANGES` bleiben als Module-Level-Variablen
(jetzt als Aliase) erhalten.

Verhaltenen-Änderung: CGNAT-Einzel-IPs (100.64.0.0/10) und `169.0.0.0/8`-artige
reservierte Supernets werden jetzt zuverlässig abgelehnt — das ist die
beabsichtigte Fix-Richtung, keine Regression.

---

## Commit-Message-Vorschlag

```
FIX BUG-CGNAT1 + FIX BUG-PRIV2: konsistente Reserved-Range-Pruefung

* is_valid_public_ipv4 lehnt jetzt CGNAT-Einzel-IPs (100.64.0.0/10, RFC 6598)
  ab. Python-stdlib markiert diese nicht als is_private, was einen
  Escape-Pfad fuer naive Upstream-Feeds auf die Blacklist oeffnete.

* is_protected_entry nutzt jetzt dieselbe Reserved-Range-Liste wie
  is_valid_public_cidr (_RESERVED_NETS). Vorher gab es zwei divergente
  Listen; 169.0.0.0/8 (ueberlappt 169.254/16 link-local) wurde nur von
  der einen abgelehnt.

+13 neue Regression-Tests; 155/155 passed.
```
