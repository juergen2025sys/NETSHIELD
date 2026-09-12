import sys as _sys; _sys.path.insert(0, "scripts")
from netshield_common import (
    load_whitelist, load_fp_set, is_in_fp_set,
    is_valid_public_ipv4, is_valid_public_cidr,
    calculate_confidence, safe_get_date,
    write_text_atomic, SqliteSeenDB,
)

# Init: Whitelist + FP-Set laden
load_whitelist()
load_fp_set()

import json, os, sys, ipaddress, bisect, re
import sqlite3, time
try:
    import resource
except ImportError:
    resource = None  # RSS diagnostics are optional on Windows
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

# ── PERF/SQLITE TESTVERSION (nur Diagnose, Outputs bleiben JSON-kanonisch) ──
# Ziel: im GitHub-Live-Log exakt sichtbar machen, wo die Laufzeit entsteht,
# und SQLite auf demselben seen_db-Snapshot benchmarken, OHNE die produktive
# Ergebnislogik zu veraendern. Die SQLite-Datei liegt nur unter /tmp und wird
# weder committed noch als Source of Truth benutzt.
_PERF_T0 = time.perf_counter()
_PERF = []
def _rss_mb():
    try:
        # Linux: ru_maxrss in KiB
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except Exception:
        return 0.0
def _perf(label, started):
    sec = time.perf_counter() - started
    _PERF.append((label, sec, _rss_mb()))
    print(f"::notice ::[PERF] {label}: {sec:.2f}s | Peak-RSS {_rss_mb():.0f} MB", flush=True)
    return sec
def _live(label, current, total=None, started=None):
    elapsed = (time.perf_counter() - started) if started is not None else 0.0
    if total:
        pct = current / total * 100.0
        rate = current / elapsed if elapsed > 0 else 0.0
        eta = (total-current) / rate if rate > 0 else 0.0
        print(f"[LIVE] {label}: {current:,}/{total:,} ({pct:.1f}%) | "
              f"{elapsed:.1f}s | {rate:,.0f}/s | ETA {eta/60:.1f} min | RSS {_rss_mb():.0f} MB", flush=True)
    else:
        print(f"[LIVE] {label}: {current:,} | {elapsed:.1f}s | RSS {_rss_mb():.0f} MB", flush=True)

print("[LIVE] Confidence gestartet: persistenter SQLite-RAM-Sparmodus bevorzugt", flush=True)
from netshield_common import generation_now
now     = generation_now()
now_str = (
    now.astimezone(ZoneInfo("Europe/Berlin"))
    .strftime("%Y-%m-%d %H:%M %Z") + " (Europe/Berlin)"
)

DB_FILE    = "seen_db.json"
SQLITE_DB_FILE = "seen_db.sqlite3"
BLACKLIST  = "combined_threat_blacklist_ipv4.txt"
OUT_40     = "blacklist_confidence40_ipv4.txt"
OUT_WATCH  = "watchlist_confidence25to39_ipv4.txt"

# ── Whitelist: Single Source of Truth aus whitelist.json ──────────
# FIX SSOT1: Hardcoded DNS_WHITELIST und PROTECTED_CIDRS durch
# whitelist.json ersetzt. Synchron mit update_combined_blacklist
# und false_positive_checker. Neue Whitelist-Einträge wirken sofort.
try:
    with open(".github/workflows/whitelist.json", encoding="utf-8") as _wl_f:
        _WHITELIST_ENTRIES = json.load(_wl_f)["entries"]
except Exception as _wl_err:
    _msg = f"whitelist.json nicht ladbar: {_wl_err} – Confidence-Berechnung abgebrochen"
    print(f"::error file=update_confidence_blacklist.yml::{_msg}")
    print(f"FEHLER: {_msg}")
    sys.exit(1)

protected_networks = []
for _entry in _WHITELIST_ENTRIES:
    try:
        protected_networks.append(ipaddress.ip_network(_entry, strict=False))
    except Exception as _suppressed:
        print(f"WARN: suppressed Exception: {_suppressed}", file=sys.stderr)
print(f"whitelist.json geladen: {len(protected_networks)} Einträge")

# ── FP-Set laden (Defense-in-Depth) ──────────────────────────────
# FIX SSOT2: state/false_positives_set.json wird von load_fp_set() oben
# bereits in die globalen Strukturen von netshield_common geladen.
# Hier nur Aliase auf die common-Strukturen anlegen, damit die
# bisherige lokale Filter-Logik unverändert weiterläuft.
# Frühere doppelte Lade-Logik entfernt (Single Source of Truth).
import netshield_common as _nc
_fp_ips      = _nc._fp_ips
_fp_networks = _nc._fp_networks
print(f"state/false_positives_set.json (via common): "
      f"{len(_fp_ips)} IPs + {len(_fp_networks)} CIDRs geladen")

# is_in_fp_set() → importiert aus netshield_common
# is_protected_entry() → importiert aus netshield_common

# ── FIX CACHE-DRIFT-STALE-FROZEN (2026-08-30, Nutzeranfrage) ────────
# Hintergrund: der seen_db-Cache oben (actions/cache/restore) kann
# nachweislich AELTER sein als der letzte combined-Commit (siehe
# BUG-CACHE-DRIFT-Kommentar weiter unten - dort bereits fuer die
# Gegenrichtung geloest: fehlende NEUE IPs nachtragen). Diese
# Ledger-Pruefung deckt die andere Richtung ab: eine IP, die der
# NEUESTE combined-Lauf bereits eingefroren/entfernt hat, aber im
# (veralteten) seen_db-Cache noch mit ihrem alten first/last-Datum
# existiert, wuerde ohne diesen Check hier trotzdem faelschlich in
# blacklist_confidence40_ipv4.txt landen. Symptom war ein
# Rueckfall-Alarm im ip_ablauf.yml-Verifikations-Job (2687 IPs am
# 2026-08-30) - verifiziert per Abgleich mit dem aktuellen
# Ledger-Stand. Erkennung: db[ip]["first"]/["last"] entspricht
# EXAKT dem im Ledger eingefrorenen Wert -> der Cache hat die
# Einfrierung schlicht noch nicht mitbekommen, die IP raus.
# Stimmt das Datum NICHT mehr ueberein, wurde die IP zwischen-
# zeitlich legitim neu bestaetigt (Ledger-Bereinigung in combined
# laeuft dann separat) - dann NICHT ausschliessen.
import glob as _glob_ledger, gzip as _gzip_ledger, io as _io_ledger

def _lade_ledger_von_release(_glob_muster):
    _teile = sorted(_glob_ledger.glob(_glob_muster))
    if not _teile:
        return {}, 0
    _puffer = _io_ledger.BytesIO()
    for _teil in _teile:
        with open(_teil, "rb") as _tf:
            while True:
                _chunk = _tf.read(1024 * 1024)
                if not _chunk:
                    break
                _puffer.write(_chunk)
    _puffer.seek(0)
    with _gzip_ledger.GzipFile(fileobj=_puffer, mode="rb") as _gz:
        _daten = json.loads(_gz.read().decode("utf-8"))
    return dict(_daten.get("entries", {})), len(_teile)

# Watchlist-Ledger wird hier bewusst nicht mehr geladen: Sentinel-
# Eintraege (last=2000-01-01) werden vor dem Stale-Frozen-Check
# immer ausgeschlossen. Der fruehere Watchlist-Zweig war daher
# unerreichbar und verursachte nur Download-/Parse-Overhead.

_active_expired_last = {}
try:
    _active_raw, _active_part_count = _lade_ledger_von_release(
        "state/active_expired_history.json.gz.part*"
    )
    for _ip_ac, _wert_ac in _active_raw.items():
        _active_expired_last[_ip_ac] = _wert_ac if isinstance(_wert_ac, dict) \
            else {"last": _wert_ac, "eingefroren_am": _wert_ac}
    print(f"Stale-Frozen-Schutz: active-Ledger geladen "
          f"({len(_active_expired_last)} Eintraege, {_active_part_count} Part(s))")
except Exception as _ex:
    print(f"WARN: active-Ledger nicht ladbar (Stale-Frozen-Schutz eingeschraenkt): {_ex}", file=sys.stderr)

skipped_stale_frozen = 0

_db_is_sqlite = False
if os.path.exists(SQLITE_DB_FILE):
    _t_sql_open = time.perf_counter()
    try:
        _check_con = sqlite3.connect(SQLITE_DB_FILE)
        try:
            _q = _check_con.execute("PRAGMA quick_check").fetchone()
            _n = _check_con.execute("SELECT COUNT(*) FROM seen_db").fetchone()[0]
        finally:
            _check_con.close()
        if not _q or _q[0] != "ok" or _n < 100000:
            raise ValueError(f"quick_check={_q!r}, rows={_n}")
        db = SqliteSeenDB(SQLITE_DB_FILE)
        _db_is_sqlite = True
        _perf("SQLite persistent open", _t_sql_open)
        print(f"[LIVE][SQL] Persistente seen_db.sqlite3 aktiv: {_n:,} IPs | "
              f"{os.path.getsize(SQLITE_DB_FILE)/1024/1024:.1f} MB", flush=True)
    except Exception as e:
        print(f"::warning file=update_confidence_blacklist.yml::"
              f"Persistente SQLite nicht verwendbar ({e}) - JSON-Fallback")
        _db_is_sqlite = False

if not _db_is_sqlite:
    if not os.path.exists(DB_FILE):
        msg = (f"Weder {SQLITE_DB_FILE} noch {DB_FILE} vorhanden – "
               f"bitte zuerst Update Combined Blacklist ausführen.")
        print(f"::warning file=update_confidence_blacklist.yml::{msg}")
        print(f"FEHLER: {msg}")
        sys.exit(1)
    _t_json_load = time.perf_counter()
    print(f"[LIVE] SQLite nicht verfuegbar; lade JSON-Fallback {DB_FILE} "
          f"({os.path.getsize(DB_FILE)/1024/1024:.1f} MB) ...", flush=True)
    with open(DB_FILE) as f:
        try:
            db = json.load(f)
        except Exception as e:
            print(f"FEHLER: seen_db.json ist korrupt oder nicht lesbar: {e}")
            print("Behalte bestehende Confidence-Blacklists und breche ab.")
            sys.exit(1)
    _perf("JSON fallback load seen_db.json", _t_json_load)
    print(f"seen_db JSON-Fallback geladen: {len(db):,} IPs", flush=True)

# Alter der seen_db prüfen.
# FIX SEEN-DB-AGE: Primär state/seen_db_meta.json verwenden (Stundengenauigkeit
# via "updated"-Feld). Der vorherige Ansatz benutzte das aktuellste
# last-Datum aus der DB; weil last nur tagesgenau ist (YYYY-MM-DD →
# strptime ergibt Mitternacht UTC), zeigte er ab ~04:30 UTC jeden
# Tag fälschlich >4,5h Alter, obwohl die Pipeline gerade erst
# bestätigt hatte. Fallback auf den DB-Vergleich nur wenn Meta
# fehlt/korrupt – Schwelle dort entsprechend großzügiger (24h+3h
# Worst-Case durch Tagesgranularität).
db_age_hours = None
_used_meta_path = False   # FIX BUG-STALE-HARDCAP: True nur wenn Meta
# erfolgreich geparst wurde. Vorher: _used_fallback = not os.path.exists(META_FILE)
# → wenn Meta existiert aber korrupt ist, landet db_age_hours vom Fallback-Pfad
# (tagesgenau, Schwelle 48h), aber _cap wurde auf STALE_HARDCAP_META_H (8h)
# gesetzt. Bei 20h altem last-Datum → 20 > 8 → sys.exit(1) obwohl Pipeline läuft.
META_FILE = "state/seen_db_meta.json"
if os.path.exists(META_FILE):
    try:
        with open(META_FILE) as _mf:
            _meta = json.load(_mf)
        _meta_upd = _meta.get("updated", "")
        if _meta_upd:
            # FIX TS-TZ: state/seen_db_meta.json["updated"] wird seit
            # update_combined_blacklist.yml in deutscher Ortszeit
            # (CET/CEST, Europe/Berlin) geschrieben, nicht mehr nur
            # UTC. Gleiches Muster wie _ts_re in
            # update_combined_blacklist.yml uebernommen, damit alte
            # (UTC) und neue (CET/CEST) Werte beide geparst werden.
            _meta_ts_m = re.match(
                r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s*(UTC|CET|CEST)',
                _meta_upd.strip())
            if _meta_ts_m:
                _meta_zone = _meta_ts_m.group(2)
                _meta_tz = timezone.utc if _meta_zone == "UTC" else ZoneInfo("Europe/Berlin")
                _meta_dt = datetime.strptime(_meta_ts_m.group(1), "%Y-%m-%d %H:%M").replace(tzinfo=_meta_tz).astimezone(timezone.utc)
            else:
                _meta_dt = datetime.strptime(_meta_upd.replace(" UTC", ""), "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            db_age_hours = (now - _meta_dt).total_seconds() / 3600
            _used_meta_path = True
            print(f"seen_db zuletzt aktualisiert: {_meta_upd} ({db_age_hours:.1f}h alt)")
            # Combined läuft alle 3h, plus Wallzeit (~30 min) plus
            # Cache-Save → 4,5h ist eine sichere Schwelle bei
            # echtem Timestamp.
            if db_age_hours > 4.5:
                print(f"WARNUNG: seen_db ist {db_age_hours:.1f}h alt – mindestens ein combined-Run wurde verpasst!")
    except Exception as _suppressed:
        print(f"WARN: state/seen_db_meta.json nicht lesbar – Fallback auf DB-last-Vergleich: {_suppressed}", file=sys.stderr)

if db_age_hours is None:
    # Fallback: aktuellstes last-Datum aus DB.
    # Nur echte HQ-Bestätigungsdaten (last != 2000-01-01) berücksichtigen,
    # damit Watchlist-IPs (last="2000-01-01") kein falsches Alarm-Alter erzeugen.
    if _db_is_sqlite:
        newest_last = db._conn.execute(
            "SELECT MAX(last) FROM seen_db WHERE last IS NOT NULL "
            "AND last <> '2000-01-01'"
        ).fetchone()[0]
    else:
        real_dates = [safe_get_date(d, "last") for d in db.values()
                      if isinstance(d, dict)
                      and safe_get_date(d, "last") != "2000-01-01"]
        newest_last = max(real_dates) if real_dates else None
    try:
        if newest_last:
            newest_dt = datetime.strptime(newest_last, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            db_age_hours = (now - newest_dt).total_seconds() / 3600
            print(f"seen_db aktuellster Eintrag (Fallback ohne Meta): {newest_last} ({db_age_hours:.1f}h alt)")
            # Schwelle für den Fallback großzügig: last ist nur tagesgenau,
            # bei 23:59 geschriebenem Eintrag und 27h später Messung wären
            # das echte 27h+ – alles darunter könnte legitim sein.
            if db_age_hours > 27:
                print(f"WARNUNG: seen_db ist {db_age_hours:.1f}h alt (Fallback) – Pipeline steht vermutlich still!")
        else:
            print("seen_db: Keine HQ-bestätigten Einträge vorhanden (nur Watchlist-IPs)")
    except Exception as _suppressed:
        print(f"WARN: suppressed Exception: {_suppressed}", file=sys.stderr)

# FIX BUG-STALE-HARDCAP: Wenn seen_db wirklich stale ist, NICHT weiterrechnen.
# Hintergrund: die WARN-Pfade oben warnen nur (4.5h Meta / 27h Fallback) und
# lassen den Workflow weiterlaufen. Bei einer mehrtaegigen combined-Outage
# (GitHub Actions down, oder mehrfacher combined-Crash) wuerde confidence
# auf einem veralteten Snapshot conf40 + watchlist neu generieren — und damit
# einen veralteten Stand als "frisch" ins Repo committen. Firewalls die conf40
# konsumieren wuerden veraltete Threats blockieren oder neue verpassen.
# Bessere Strategie: bei extrem stalen Daten KEINEN Output schreiben. Die
# alten committeten Dateien bleiben stehen — Konsumenten haben dann ehrlich
# alte aber konsistente Daten, nicht frisch-aussehende veraltete.
# Schwellen:
#   Meta-basiert (genau, minutengenau):  8h = 2 verpasste combined-Runs
#   Fallback (last-Datum, tagesgenau):  48h = 2 Tage Pipeline-Stillstand
# Das gibt Glitches (1 verpasster Run, ~3-4h) genug Toleranz und schlaegt
# erst bei echtem Pipeline-Problem zu.
STALE_HARDCAP_META_H     = 8.0
STALE_HARDCAP_FALLBACK_H = 48.0
if db_age_hours is not None:
    _cap = STALE_HARDCAP_META_H if _used_meta_path else STALE_HARDCAP_FALLBACK_H
    if db_age_hours > _cap:
        _stale_msg = (
            f"seen_db ist {db_age_hours:.1f}h alt (Schwelle: {_cap:.0f}h, "
            f"{'Meta' if _used_meta_path else 'Fallback'}-Quelle). "
            f"confidence-Workflow wird abgebrochen, damit keine veralteten "
            f"Daten als 'frisch' ins Repo committet werden. Bestehende "
            f"{OUT_40} + {OUT_WATCH} bleiben unveraendert. "
            f"Ursache vermutlich combined-Workflow-Stillstand: bitte "
            f"update_combined_blacklist.yml-Runs pruefen."
        )
        print(f"::error file=update_confidence_blacklist.yml::{_stale_msg}")
        print(f"FEHLER: {_stale_msg}")
        sys.exit(1)

# CHANGE ZWEI-FESTE-PARTS: Hauptdatei wird nicht mehr committet –
# die Parts (part1/part2) sind kanonisch. Der Guard akzeptiert daher
# auch den Fall "nur Parts vorhanden"; die Lese-Schleife unten liest
# ohnehin [Hauptdatei] + alle Parts mit Existenzfilter.
import glob as _guard_glob
if (not os.path.exists(BLACKLIST)
        and not _guard_glob.glob("combined_threat_blacklist_ipv4_part*.txt")):
    msg = f"{BLACKLIST} und Parts nicht gefunden – combined-Workflow muss zuerst laufen."
    print(f"::warning file=update_confidence_blacklist.yml::{msg}")
    print(f"FEHLER: {msg}")
    sys.exit(1)

# combined_threat_blacklist_ipv4.txt wird bereits beim Schreiben in
# update_combined_blacklist mit is_protected_entry() gefiltert →
# erneute Prüfung hier wäre 502 Netzwerk-Checks × 4,5M IPs ≈ 10 Min Zeitverschwendung.
#
# FIX BUG-TRUNCATE-PARTS: Sobald die Vollliste >= 100 MB GitHub-Push-
# Limit erreicht, schreibt update_combined_blacklist die Hauptdatei
# truncatiert (nur die ersten N IPs) und verteilt die vollstaendige
# Liste auf combined_threat_blacklist_ipv4_part*.txt. Wenn wir hier
# nur die Hauptdatei lesen, verlieren IPs die ausschliesslich in den
# Parts stehen ihren Confidence-Score und landen weder in
# blacklist_confidence40 noch in der Watchlist – obwohl sie in
# seen_db vorhanden sind.
# Loesung: Hauptdatei + alle Parts einlesen, dedupen via set-Update.
# Das ist auch unter Schwelle (Parts existieren nicht) safe – glob
# matcht dann nichts. Solange Combined unter SPLIT_THRESHOLD bleibt,
# ist die Hauptdatei ohnehin vollstaendig und der Loop ist ein No-Op.
import glob as _glob
combined_ips = set()
_sources_read = [BLACKLIST] + sorted(
    _glob.glob("combined_threat_blacklist_ipv4_part*.txt"))
for _src in _sources_read:
    if not os.path.exists(_src):
        continue
    with open(_src) as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                valid = is_valid_public_cidr(s) if "/" in s else is_valid_public_ipv4(s)
                if valid and not is_in_fp_set(s):
                    combined_ips.add(s)
if len(_sources_read) > 1:
    print(f"Combined Blacklist: {len(combined_ips)} IPs "
          f"(Hauptdatei + {len(_sources_read) - 1} Part(s))")
else:
    print(f"Combined Blacklist: {len(combined_ips)} IPs")

# ── FP-Vorfilter für combined_ips (einmalig, statt pro IP im Inner-Loop) ─
# combined_threat_blacklist_ipv4.txt ist zwar bereits mit is_in_fp_set() gefiltert,
# aber es kann einen Timing-Gap geben (FP-Checker läuft nach Combined).
# Statt is_in_fp_set(ip) im Inner-Loop (4,5M × ~2945 Netzwerk-Checks ≈ 47 Min),
# filtern wir combined_ips EINMAL vorab via Binary-Search O(N × log K).
#
# FIX BUG-11: Intervalle VOR bisect mergen. Ohne Merge findet
# bisect_right nur das zuletzt startende Intervall mit start <= ip.
# Bei überlappenden FP-CIDRs würde die IP in einem Eltern-CIDR
# übersehen. Merging garantiert: jeder IP-Treffer landet im
# umschließenden Intervall.
if _fp_ips:
    combined_ips -= _fp_ips
if _fp_networks:
    _intervals_raw = sorted(
        (int(n.network_address), int(n.broadcast_address))
        for n in _fp_networks
    )
    # Intervall-Merge: überlappende/benachbarte Ranges zusammenführen
    _intervals = []
    for _lo, _hi in _intervals_raw:
        if _intervals and _lo <= _intervals[-1][1] + 1:
            _intervals[-1] = (_intervals[-1][0], max(_intervals[-1][1], _hi))
        else:
            _intervals.append((_lo, _hi))
    _starts = [iv[0] for iv in _intervals]
    _fp_cidr_hits = set()
    for _ip in combined_ips:
        try:
            # FIX BUG-11 zusatz: bei CIDR-Einträgen das gesamte Intervall
            # gegen FP-Ranges prüfen, nicht nur die Netzadresse.
            if "/" in _ip:
                _net = ipaddress.ip_network(_ip, strict=False)
                _lo = int(_net.network_address)
                _hi = int(_net.broadcast_address)
            else:
                _lo = _hi = int(ipaddress.ip_address(_ip))
            _pos = bisect.bisect_right(_starts, _hi) - 1
            if _pos >= 0 and _intervals[_pos][1] >= _lo:
                _fp_cidr_hits.add(_ip)
        except Exception:
            pass
    if _fp_cidr_hits:
        combined_ips -= _fp_cidr_hits
        print(f"FP-Timing-Gap-Filter: {len(_fp_cidr_hits)} IPs aus combined_ips entfernt")
print(f"Combined Blacklist nach FP-Filter: {len(combined_ips)} IPs")

# ── Whitelist-Defense-in-Depth-Filter ─────────────────────────────
# FIX BUG-WL1-PROPAGATION: combined_threat_blacklist_ipv4.txt wird
# zwar im Upstream gefiltert, aber wenn der Upstream-Filter ausfällt
# (z.B. BUG-WL1: load_whitelist() im Job-Step vergessen → is_whitelisted
# liefert False → Filter wirkungslos), propagiert der Leak in die
# Confidence-Blacklist OHNE dass dieser Workflow ihn bemerkt.
# Genau das ist am 2026-04-26 08:37 UTC passiert: alle drei Output-
# Dateien (combined, active, confidence40) enthielten dieselben
# whitelisted Google-/Microsoft-IPs.
# Lösung: Eigenständiger Whitelist-Filter via Merge+Bisect, identisch
# zum FP-Timing-Gap-Filter darüber. Performance: O(N × log K) – bei
# 4,5M IPs gegen ~437 gemergte Whitelist-Intervalle <1s. Defense-in-
# Depth ist hier den Kosten wert.
if protected_networks:
    _wl_intervals_raw = sorted(
        (int(n.network_address), int(n.broadcast_address))
        for n in protected_networks
    )
    _wl_intervals = []
    for _lo, _hi in _wl_intervals_raw:
        if _wl_intervals and _lo <= _wl_intervals[-1][1] + 1:
            _wl_intervals[-1] = (_wl_intervals[-1][0], max(_wl_intervals[-1][1], _hi))
        else:
            _wl_intervals.append((_lo, _hi))
    _wl_starts = [iv[0] for iv in _wl_intervals]
    _wl_hits = set()
    for _ip in combined_ips:
        try:
            if "/" in _ip:
                _net = ipaddress.ip_network(_ip, strict=False)
                _lo = int(_net.network_address)
                _hi = int(_net.broadcast_address)
            else:
                _lo = _hi = int(ipaddress.ip_address(_ip))
            _pos = bisect.bisect_right(_wl_starts, _hi) - 1
            if _pos >= 0 and _wl_intervals[_pos][1] >= _lo:
                _wl_hits.add(_ip)
        except Exception:
            pass
    if _wl_hits:
        combined_ips -= _wl_hits
        # Lautes Logging: Wenn dieser Filter zuschlägt, liegt
        # upstream ein BUG-WL1-artiges Problem vor – das soll im
        # Workflow-Log auffallen, auch wenn die Filterung selbst
        # erfolgreich greift.
        _sample = sorted(_wl_hits)[:5]
        print(f"::warning file=update_confidence_blacklist.yml::"
              f"Whitelist-Leak im Upstream erkannt und gefiltert: "
              f"{len(_wl_hits)} IPs (Beispiele: {', '.join(_sample)}). "
              f"BUG-WL1-Klasse – Combined-Blacklist-Generator prüfen.")
        print(f"Whitelist-Defense-in-Depth: {len(_wl_hits)} IPs aus combined_ips entfernt")
    else:
        print(f"Whitelist-Defense-in-Depth: 0 Treffer (Upstream sauber)")
print(f"Combined Blacklist nach Whitelist-Filter: {len(combined_ips)} IPs")

# ── SQLITE-BENCHMARK (TESTVERSION, KEIN Einfluss auf Outputs) ─────
# Baut einmalig eine temporaere SQLite-Projektion der fuer Confidence
# benoetigten Felder. Damit messen wir live: Importdauer, DB-Groesse,
# SQL-Scan und Lookup-Geschwindigkeit. Erst wenn diese Zahlen im echten
# GitHub-Runner klar besser sind, lohnt sich die Migration im Combined-
# Writer. Wichtig: Weil wir hier aus JSON importieren, wird DIESER Test-
# Run absichtlich laenger; er misst das Potential fuer zukuenftige Runs,
# in denen Combined SQLite direkt pflegen wuerde.
SQLITE_TEST = os.environ.get("NETSHIELD_SQLITE_TEST", "1") != "0"
_sqlite_stats = {}
if SQLITE_TEST:
    _sql_path = "/tmp/netshield_seen_confidence_test.sqlite"
    try:
        if os.path.exists(_sql_path):
            os.remove(_sql_path)
        _t_sql_build = time.perf_counter()
        print(f"[LIVE][SQL] Erzeuge temporaere SQLite-Projektion: {_sql_path}", flush=True)
        _con = sqlite3.connect(_sql_path)
        _cur = _con.cursor()
        _cur.executescript("""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            PRAGMA temp_store=MEMORY;
            PRAGMA locking_mode=EXCLUSIVE;
            PRAGMA cache_size=-262144;
            CREATE TABLE seen (
                ip TEXT PRIMARY KEY,
                hq INTEGER NOT NULL,
                feed_count INTEGER NOT NULL,
                today_count INTEGER NOT NULL,
                days_seen INTEGER NOT NULL,
                last_seen TEXT NOT NULL,
                first_seen TEXT NOT NULL
            ) WITHOUT ROWID;
        """)
        _batch=[]
        _sql_n=0
        _sql_total=len(db)
        _sql_live_t=time.perf_counter()
        for _sip, _sd in db.items():
            if not isinstance(_sd, dict):
                continue
            _slast=safe_get_date(_sd, "last")
            _sfirst=safe_get_date(_sd, "first", _slast)
            _batch.append((
                _sip, 1 if _sd.get("hq", False) else 0,
                len(_sd.get("feeds", [])), int(_sd.get("today_count", 0) or 0),
                int(_sd.get("days_seen", 1) or 1), _slast, _sfirst
            ))
            if len(_batch) >= 50000:
                _cur.executemany("INSERT INTO seen VALUES (?,?,?,?,?,?,?)", _batch)
                _sql_n += len(_batch); _batch.clear()
                if _sql_n % 500000 == 0:
                    _live("SQLite import", _sql_n, _sql_total, _sql_live_t)
        if _batch:
            _cur.executemany("INSERT INTO seen VALUES (?,?,?,?,?,?,?)", _batch)
            _sql_n += len(_batch); _batch.clear()
        _con.commit()
        _sqlite_stats["build_s"]=_perf("SQLite build aus bereits geparstem JSON", _t_sql_build)
        _sqlite_stats["size_mb"]=os.path.getsize(_sql_path)/1024/1024
        print(f"[LIVE][SQL] SQLite fertig: {_sql_n:,} Zeilen | {_sqlite_stats['size_mb']:.1f} MB", flush=True)

        # Indexe entsprechen den wahrscheinlich nuetzlichen Filterpfaden.
        _t_idx=time.perf_counter()
        _cur.execute("CREATE INDEX idx_seen_last ON seen(last_seen)")
        _cur.execute("CREATE INDEX idx_seen_first ON seen(first_seen)")
        _con.commit()
        _sqlite_stats["index_s"]=_perf("SQLite Indexaufbau last/first", _t_idx)

        _t_q=time.perf_counter()
        _sql_non_sentinel=_cur.execute(
            "SELECT COUNT(*) FROM seen WHERE last_seen <> '2000-01-01'"
        ).fetchone()[0]
        _sqlite_stats["count_s"]=_perf("SQLite COUNT non-sentinel", _t_q)
        print(f"[LIVE][SQL] non-sentinel: {_sql_non_sentinel:,}", flush=True)

        # Membership-Lookups gegen eine Stichprobe aus combined_ips.
        _probe=list(combined_ips)[:100000]
        _t_probe=time.perf_counter(); _hits=0
        for _pip in _probe:
            if _cur.execute("SELECT 1 FROM seen WHERE ip=?", (_pip,)).fetchone():
                _hits += 1
        _sqlite_stats["lookup100k_s"]=_perf("SQLite 100k PK-Lookups", _t_probe)
        print(f"[LIVE][SQL] PK-Probe: {_hits:,}/{len(_probe):,} Treffer", flush=True)
        _con.close()
    except Exception as _sql_e:
        print(f"::warning file=update_confidence_blacklist.yml::SQLite-Test fehlgeschlagen: {_sql_e}", flush=True)
        print(f"WARNUNG [SQLITE-TEST]: {_sql_e} -- produktive JSON-Logik laeuft weiter.", flush=True)
    finally:
        # Testdatei nicht in Git/Workspace liegen lassen.
        try:
            if os.path.exists(_sql_path):
                os.remove(_sql_path)
        except Exception:
            pass
else:
    print("[LIVE][SQL] SQLite-Test per NETSHIELD_SQLITE_TEST=0 deaktiviert", flush=True)

# ══════════════════════════════════════════════════════════════════
# KONFIDENZ-MODELL
#
# blacklist_confidence40 = mittleres bis hohes Vertrauen (≥40 Punkte)
#   Mehr IPs als active_blacklist, geeignet für zusätzliche Filterregeln.
# watchlist              = neue/unsichere Bedrohungen (25–39 Punkte)
#
# Score setzt sich aus 4 unabhängigen Dimensionen zusammen:
#
# [A] QUELLEN-QUALITÄT (max. 40 Punkte) – wie vertrauenswürdig sind
#     die Feeds die diese IP gemeldet haben?
#       hq=True (je in einem HQ-Feed)          → 40
#       today_count >= 5 (heute 5+ Feeds)      → 35
#       today_count >= 3 (heute 3+ Feeds)      → 28
#       today_count >= 2 (heute 2+ Feeds)      → 20
#       feed_count >= 5 (akkum. 5+ Feeds)      → 15
#       feed_count >= 3 (akkum. 3+ Feeds)      → 10
#       feed_count >= 2 (akkum. 2 Feeds)       →  5
#       1 Feed total                            →  0
#
# [B] AKTUALITÄT (max. 30 Punkte) – wie frisch ist die letzte
#     *starke* Bestätigung? ("last" wird in update_combined_blacklist
#     ausschließlich gesetzt wenn mindestens 1 HQ-Feed die IP heute meldet)
#       last_seen ≤ 1 Tag   → 30
#       last_seen ≤ 3 Tage  → 25
#       last_seen ≤ 7 Tage  → 20
#       last_seen ≤ 14 Tage → 12
#       last_seen ≤ 30 Tage →  6
#       last_seen > 30 Tage →  0
#
# [C] PERSISTENZ (max. 20 Punkte) – wurde die IP über mehrere Tage
#     unabhängig bestätigt? (days_seen = Anzahl verschiedener Tage
#     an denen "stark bestätigt" wurde)
#       days_seen >= 14     → 20
#       days_seen >= 7      → 15
#       days_seen >= 3      → 10
#       days_seen >= 2      →  6
#       days_seen == 1      →  2
#
# [D] BEKANNT SEIT (max. 10 Punkte) – wie lange ist die IP schon
#     im System?
#       bekannt ≥ 90 Tage   → 10
#       bekannt ≥ 30 Tage   →  6
#       bekannt ≥ 14 Tage   →  3
#       bekannt < 14 Tage   →  0
#
# Gesamt max. 100 Punkte.
# Schwellwerte:
#   conf >= 40 → blacklist_confidence40 (mittleres/hohes Vertrauen)
#   conf 25–39 → watchlist
#   conf < 25  → ignoriert
#
# Hinweis: active_blacklist_ipv4.txt (OPNsense) verwendet conf >= 65
# und ist damit deutlich restriktiver (nur echte HQ-Bedrohungen).
# ══════════════════════════════════════════════════════════════════

# FIX SENTINEL-WATCHLIST (2026-09-09, Nutzerfund via Workflow-Health-
# Report): IPs mit last="2000-01-01" (Sentinel, siehe Guard weiter
# unten) wurden bisher komplett aus confidence40 UND Watchlist
# ausgeschlossen - fachlich falsch, denn "schwach bestaetigt,
# wartet auf Neubestaetigung" ist exakt die Watchlist-Definition.
# Betraf zuletzt 2.817.950 IPs (26% von combined) und hat die
# Watchlist auf 0 Eintraege geleert. Fester Boden-Score statt
# berechnetem Score: verhindert (wie im urspruenglichen Fix
# beabsichtigt) jede Score-Inflation Richtung confidence40,
# unabhaengig von is_hq/feed_count/today_count.
SENTINEL_WATCHLIST_SCORE = 25

confidence40 = []
confidence25 = []
skipped      = 0
skipped_watchlist = 0

_t_conf_loop = time.perf_counter()
_conf_total = len(db)
_conf_n = 0

if _db_is_sqlite:
    # FIX PERF-SCORING-SQL 31.08.2026: SQLite liefert nur die sieben
    # fuer Confidence benoetigten Werte. Kein volles Dict und keine
    # json.loads()-Aufrufe fuer feeds/hq_feed_names pro Zeile.
    _conf_source = db.iter_scoring_rows()
else:
    # JSON-Fallback bleibt semantisch identisch.
    def _iter_json_scoring_rows():
        for _ip, _data in db.items():
            if not isinstance(_data, dict):
                yield (_ip, None, None, None, -1, None, None)
                continue
            _last = safe_get_date(_data, "last")
            _first = safe_get_date(_data, "first", _last)
            _feeds = _data.get("feeds", [])
            if not isinstance(_feeds, list):
                yield (_ip, _first, _last, _data.get("hq", False), -1,
                       _data.get("today_count", 0), _data.get("days_seen", 1))
                continue
            yield (_ip, _first, _last, _data.get("hq", False), len(_feeds),
                   _data.get("today_count", 0), _data.get("days_seen", 1))
    _conf_source = _iter_json_scoring_rows()

print(f"[LIVE] Starte Confidence-Scan ueber {_conf_total:,} seen_db-Eintraege ...", flush=True)
for ip, first_seen, last_seen, is_hq, feed_count, today_count, days_seen in _conf_source:
    _conf_n += 1
    if _conf_n % 500000 == 0:
        _live("Confidence-Scan", _conf_n, _conf_total, _t_conf_loop)
    try:
        if feed_count == -1:
            skipped += 1
            continue

        # FIX SQLITE-JSON-DATE-PARITY 31.08.2026: iter_scoring_rows()
        # liefert rohe SQLite-Werte. Der JSON-Fallback normalisiert
        # last via safe_get_date(..., default=Sentinel) und first mit
        # last als Fallback. Ohne diese zwei Zeilen wurden NULL oder
        # nicht-ISO first/last im SQLite-Pfad anders behandelt als im
        # JSON-Pfad. Beide Quellen haben jetzt identische Semantik.
        last_seen = safe_get_date({"last": last_seen}, "last")
        first_seen = safe_get_date({"first": first_seen}, "first", last_seen)

        if ip not in combined_ips:
            # combined_ips wurde bereits beim Laden auf is_protected_entry()
            # und is_in_fp_set() vorgeprueft -> keine weiteren Einzelchecks noetig.
            continue

        try:
            last_dt  = datetime.strptime(last_seen,  "%Y-%m-%d").replace(tzinfo=timezone.utc)
            first_dt = datetime.strptime(first_seen, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            skipped += 1
            continue

        # Sentinel-Guard: last="2000-01-01" markiert Einträge ohne echtes
        # "last seen"-Datum. Bei einer IP die gleichzeitig in combined_ips
        # steht ist das inkonsistent → keine verlässliche Score-Grundlage.
        #
        # FIX BUG#2 (erweitert): Der alte Guard `last=="2000-01-01" and
        # not is_hq` ließ den Fall is_hq=True + Sentinel-Datum durch.
        # Folge: score_a=40 (HQ) + score_d=10 (Sentinel-first triggert
        # vollen Alter-Bonus) + score_c≥2 = Score ≥52 → fälschlicher
        # confidence40-Eintrag. Der is_hq-Check ist entfernt: das
        # Sentinel-Datum allein ist das kanonische Ausschluss-Signal,
        # unabhängig von anderen Feldern.
        if last_seen == "2000-01-01":
            confidence25.append((ip, SENTINEL_WATCHLIST_SCORE))
            skipped_watchlist += 1
            continue

        days_since_last = (now - last_dt).days
        # FIX BUG-2: first="2000-01-01" ist ein Sentinel, kein echtes Datum.
        # Ohne Neutralisierung ergibt (now - first_dt) ≈ 9600 Tage →
        # days_known ≥ 90 → voller Alter-Bonus +10. Eine Watchlist-IP
        # ohne verwertbares first-Datum bekäme Score-Inflation von 10 Punkten
        # für ein fiktives "26 Jahre bekannt"-Alter. Korrekt: days_known=0
        # → Alter-Score 0, weil die Dimension keine verwertbare Info hat.
        if first_seen == "2000-01-01":
            days_known = 0
        else:
            days_known = (now - first_dt).days + 1

        # FIX DRY: Inline-Scoring entfernt, zentrale Funktion aus
        # netshield_common aufgerufen. Entspricht dem identischen
        # Fix in update_combined_blacklist.yml. Beseitigt das
        # Drift-Risiko (Score-Logik war vorher dreifach dupliziert)
        # und ist crash-sicher gegen korrupte seen_db-Werte.
        conf = calculate_confidence(
            is_hq=is_hq,
            today_count=today_count,
            feed_count=feed_count,
            days_since_last=days_since_last,
            days_seen=days_seen,
            days_known=days_known,
        )

        # FIX CACHE-DRIFT-STALE-FROZEN: db[ip] stammt aus dem
        # (moeglicherweise veralteten) seen_db-Cache. Pruefen, ob
        # first/last exakt dem Wert entspricht, mit dem der
        # NEUESTE combined-Lauf diese IP bereits eingefroren hat -
        # falls ja, hat der Cache die Einfrierung nur noch nicht
        # mitbekommen, die IP gehoert NICHT in den Output.
        _active_frozen = _active_expired_last.get(ip)
        if _active_frozen is not None and _active_frozen.get("last") == last_seen:
            skipped_stale_frozen += 1
            continue

        # is_protected_entry()-Guard hier entfernt: Zugehörigkeit zu combined_ips
        # garantiert bereits dass die IP kein geschützter Eintrag ist.
        if conf >= 40:
            confidence40.append((ip, conf))
        elif conf >= 25:
            confidence25.append((ip, conf))
    except Exception as _corrupt:
        skipped += 1
        print(f"WARN: Korrupter seen_db-Eintrag {ip}: {_corrupt}", file=sys.stderr)
        continue

_perf("Confidence Python-Scan", _t_conf_loop)

# Cache-Drift: keine synthetischen HQ-Scores mehr erfinden.
# combined.txt beweist nur Mitgliedschaft, nicht HQ-Status.
print("Cache-Drift-Autoheilung: deaktiviert (keine erfundenen HQ-Scores).")

_t_sort = time.perf_counter()
print(f"[LIVE] Sortiere {len(confidence40):,} conf40 + {len(confidence25):,} watchlist Eintraege ...", flush=True)
confidence40.sort(key=lambda x: (-x[1], x[0]))
confidence25.sort(key=lambda x: (-x[1], x[0]))
_perf("Sortierung Confidence-Ergebnisse", _t_sort)

print(f"Konfidenz ≥40 (→ confidence40-Datei): {len(confidence40)} IPs")
print(f"Stale-Frozen-Schutz: {skipped_stale_frozen} IP(s) ausgeschlossen "
      f"(seen_db-Cache veraltet - laut aktuellem Ledger bereits eingefroren)")
print(f"Konfidenz 25-39 (→ watchlist):         {len(confidence25)} IPs")
print(f"Sentinel-Ausschluss (last=2000-01-01):  {skipped_watchlist} IPs (kein verwertbares Datum)")
print(f"Übersprungen:                          {skipped} IPs (Datumsfehler)")

# ── Leerungsschutz confidence40 ───────────────────────────────────
# Verhindert das Überschreiben bei leerem/korruptem seen_db-Cache.
# Schwelle identisch mit active_blacklist in update_combined_blacklist.yml.
MIN_CONF40 = 100
if len(confidence40) < MIN_CONF40:
    msg = (f"Nur {len(confidence40)} IPs in confidence40 (< {MIN_CONF40}) – "
           f"Leerungsschutz aktiv, {OUT_40} wird NICHT überschrieben.")
    print(f"::warning file=update_confidence_blacklist.yml::{msg}")
    print(f"WARNUNG: {msg}")
    sys.exit(1)

# FIX ATOMIC: write_text_atomic statt open("w") – garantiert dass
# die Datei bei Runner-Kill/OOM komplett alt oder komplett neu bleibt,
# niemals halb geschrieben. Reihenfolge ist nach Confidence-Score
# absteigend (nicht nach IP), deshalb write_text_atomic statt
# write_ip_list (das nach IP sortieren würde).
#
# FIX HARD-LIMIT-CONF40: Groesse VOR dem Schreiben schaetzen und
# bei >= HARD_LIMIT_MB Truncate-Fallback + Parts anwenden, analog
# zur Logik in update_combined_blacklist.yml. Ohne diesen Schutz
# wuerde git push hart fehlschlagen sobald conf40 die 100 MB
# GitHub-Push-Grenze reisst (derzeit ~57 MB, Wachstum proportional
# zu combined). Hauptdatei bleibt der Legacy-Pfad (kompletter
# Score-sortierter Inhalt solange unter 100 MB), Parts decken die
# Vollstaendigkeit bei jeder Groesse ab (kanonische Downloads).
# Reihenfolge im File: Score-sortiert absteigend bleibt erhalten;
# Parts werden in Score-Bereiche aufgeteilt (Part 1 = hoechste Scores).
HARD_LIMIT_MB      = 100  # GitHub Push-Limit
TRUNCATE_TARGET_MB = 95   # Sicherheitspuffer unter HARD_LIMIT_MB

# Sample-basierte Avg-Schaetzung (stratifiziert, vermeidet IP-Laengen-
# Bias durch sortierte Reihenfolge). Identische Methode wie combined.
_step = max(1, len(confidence40) // 10_000)
_sample = confidence40[::_step][:10_000]
_avg_line = (sum(len(ip) + 1 for ip, _ in _sample) / len(_sample)) if _sample else 16
_header_overhead = 512
_conf40_estimated_mb = (
    len(confidence40) * _avg_line * 1.02 + _header_overhead
) / 1024 / 1024
print(f"\nGeschaetzte Groesse confidence40 (ungesplittet): {_conf40_estimated_mb:.1f} MB")

if _conf40_estimated_mb >= HARD_LIMIT_MB:
    # Truncate: hoechste Scores zuerst, Rest in Parts
    _max_ips = int((TRUNCATE_TARGET_MB * 1024 * 1024 - _header_overhead) / _avg_line)
    _max_ips = max(1000, min(_max_ips, len(confidence40)))
    _truncated = confidence40[:_max_ips]
    _dropped = len(confidence40) - _max_ips
    _trunc_msg = (
        f"Hauptdatei wuerde {_conf40_estimated_mb:.1f} MB "
        f"(>= {HARD_LIMIT_MB} MB GitHub-Limit) – TRUNCATE auf "
        f"{_max_ips:,} IPs (~{TRUNCATE_TARGET_MB} MB). "
        f"{_dropped:,} IPs ausschliesslich in Parts. Consumer auf Parts umstellen!"
    )
    print(f"::warning file=update_confidence_blacklist.yml::{_trunc_msg}")
    print(f"WARNUNG: {_trunc_msg}")
    _conf40_body = (
        f"# NETSHIELD Blacklist – Mittleres/Hohes Vertrauen (Score ≥40/100) [TRUNCATED]\n"
        f"# Aktualisiert: {now_str}\n"
        f"# Scoring: Quellen-Qualität(40) + Aktualität(30) + Persistenz(20) + Alter(10)\n"
        f"# Eintraege in dieser Datei: {_max_ips} (von {len(confidence40)} gesamt)\n"
        f"# WICHTIG: {_dropped} IPs NICHT in dieser Datei (GitHub-Hard-Limit 100 MB).\n"
        f"# Fuer vollstaendigen Schutz: blacklist_confidence40_ipv4_part*.txt verwenden.\n\n"
        + "".join(f"{ip}\n" for ip, conf in _truncated)
    )
else:
    _conf40_body = (
        f"# NETSHIELD Blacklist – Mittleres/Hohes Vertrauen (Score ≥40/100)\n"
        f"# Aktualisiert: {now_str}\n"
        f"# Scoring: Quellen-Qualität(40) + Aktualität(30) + Persistenz(20) + Alter(10)\n"
        f"# Eintraege: {len(confidence40)}\n\n"
        + "".join(f"{ip}\n" for ip, conf in confidence40)
    )
write_text_atomic(OUT_40, _conf40_body)
_conf40_main_mb = os.path.getsize(OUT_40) / 1024 / 1024
print(f"{OUT_40} (tatsaechlich): {_conf40_main_mb:.1f} MB")

# Die Hauptdatei wird nicht committet: beide Download-Parts immer bauen.
# Feste URLs und Score-Reihenfolge bleiben bei jeder Listengroesse erhalten.
_existing_parts_conf40 = sorted(_glob.glob("blacklist_confidence40_ipv4_part*.txt"))
_chunk_size = (len(confidence40) + 1) // 2
_new_parts = []
_written_count = 0
for _idx in range(2):
    _start = _idx * _chunk_size
    _end = min(_start + _chunk_size, len(confidence40))
    _part_name = f"blacklist_confidence40_ipv4_part{_idx + 1}.txt"
    _part_body = (
        f"# NETSHIELD Confidence-40 Blacklist – Part {_idx + 1}/2\n"
        f"# Aktualisiert: {now_str}\n"
        f"# Score-Bereich: {confidence40[_start][1]} bis {confidence40[_end - 1][1]}\n"
        f"# Eintraege: {_end - _start}\n"
        f"# Fuer vollstaendigen Schutz beide Parts verwenden.\n\n"
        + "".join(f"{ip}\n" for ip, conf in confidence40[_start:_end])
    )
    _part_mb = len(_part_body.encode("utf-8")) / 1024 / 1024
    if _part_mb >= HARD_LIMIT_MB:
        raise RuntimeError(f"{_part_name}: {_part_mb:.1f} MiB erreicht GitHub-Dateilimit")
    if _part_mb >= 90:
        print(f"::warning::{_part_name}: {_part_mb:.1f} MiB, nahe am Dateilimit")
    write_text_atomic(_part_name, _part_body)
    _new_parts.append(_part_name)
    _written_count += _end - _start
    print(f"{_part_name}: {_end - _start:,} IPs, {_part_mb:.1f} MiB")
if len(_new_parts) != 2 or _written_count != len(confidence40):
    raise RuntimeError("Confidence-Parts unvollstaendig; keine Veroeffentlichung")
for _old in _existing_parts_conf40:
    if _old not in _new_parts:
        os.unlink(_old)
# Small-result protection must never retain a newly protected/promoted host.
watch_ips = [ip for ip, score in confidence25]
watch_retained = False
MIN_WATCH = 10
if len(watch_ips) < MIN_WATCH and os.path.exists(OUT_WATCH):
    promoted = {ip for ip, score in confidence40}
    with open(OUT_WATCH, encoding="utf-8") as previous:
        retained = {line.strip().removesuffix('/32') for line in previous
                    if line.strip() and not line.lstrip().startswith('#')}
    # combined_ips has already passed the current IPv4, whitelist and FP
    # filters. Removing promoted hosts keeps the two outputs disjoint.
    retained.intersection_update(combined_ips)
    retained.difference_update(promoted)
    retained.difference_update(watch_ips)
    watch_retained = bool(retained)
    watch_ips.extend(sorted(retained))
    print(f"Watchlist-Leerungsschutz: {len(retained)} gepruefte Alt-Eintraege beibehalten")
_watch_body = (
    f"# NETSHIELD Watchlist – Niedriges Vertrauen (Score 25-39/100)\n"
    f"# Aktualisiert: {now_str}\n"
    f"# Eintraege: {len(watch_ips)}\n"
    f"# Geprueften Altbestand beibehalten: {str(watch_retained).lower()}\n\n"
    + "".join(f"{ip}\n" for ip in watch_ips)
)
write_text_atomic(OUT_WATCH, _watch_body)
print(f"Fertig: {len(confidence40)} IPs (conf≥40) | {len(watch_ips)} IPs (Watchlist veroeffentlicht)")

# Record the scoring time and content hashes for this Combined generation.
import hashlib as _hashlib
def _file_hash(_path):
    try:
        with open(_path, 'rb') as _stream:
            return _hashlib.file_digest(_stream, 'sha256').hexdigest()
    except OSError:
        return ''
write_text_atomic('state/confidence_generation.json', json.dumps({
    'generated_at_epoch': int(now.timestamp()),
    'combined_sha256': _file_hash(BLACKLIST),
    'combined_parts_sha256': sorted((_file_hash(p) for p in _glob.glob('combined_threat_blacklist_ipv4_part*.txt'))),
    'active_sha256': _file_hash('active_blacklist_ipv4.txt'),
    'confidence_sha256': _file_hash(OUT_40),
    'watchlist_sha256': _file_hash(OUT_WATCH),
}, indent=2))

# ── LIVE-PERF-ZUSAMMENFASSUNG ────────────────────────────────────
_total_s = time.perf_counter() - _PERF_T0
print("\n========== NETSHIELD LIVE PERFORMANCE REPORT ==========", flush=True)
for _label, _sec, _rss in _PERF:
    print(f"[PERF-SUMMARY] {_label:<42} {_sec:8.2f}s | Peak-RSS {_rss:7.0f} MB", flush=True)
if _sqlite_stats:
    print(f"[PERF-SUMMARY] SQLite temporaere DB-Groesse         {_sqlite_stats.get('size_mb', 0):8.1f} MB", flush=True)
    print("[PERF-SUMMARY] HINWEIS: SQLite-Build ist Test-Overhead. Fuer echten Speedup muss Combined SQLite direkt schreiben/pflegen.", flush=True)
print(f"[PERF-SUMMARY] Python-Block gesamt                  {_total_s:8.2f}s ({_total_s/60:.2f} min)", flush=True)
print("========================================================", flush=True)
