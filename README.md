
::: {align="center"}
`<img src=".github/assets/banner.svg" alt="NETSHIELD — Automated Threat Intelligence" width="100%">`{=html}

`<br>`{=html}

[![Combined](https://img.shields.io/github/actions/workflow/status/juergen2025sys/NETSHIELD/update_combined_blacklist.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Combined&labelColor=2563EB&color=16C784)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_combined_blacklist.yml)
[![Feed
Health](https://img.shields.io/github/actions/workflow/status/juergen2025sys/NETSHIELD/feed_health_monitor.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Feed%20Health&labelColor=7C3AED&color=16C784)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/feed_health_monitor.yml)
[![Confidence](https://img.shields.io/github/actions/workflow/status/juergen2025sys/NETSHIELD/update_confidence_blacklist.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Confidence&labelColor=00A7E1&color=16C784)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_confidence_blacklist.yml)
[![False
Positive](https://img.shields.io/github/actions/workflow/status/juergen2025sys/NETSHIELD/false_positive_checker.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=False%20Positive&labelColor=F97316&color=16C784)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/false_positive_checker.yml)

`<br>`{=html}

## ⚡ SCHNELL · 🌍 GLOBAL · 🛡️ AUTOMATISIERT

**Threat-Intelligence aus hunderten Quellen --- bewertet, bereinigt und
direkt als Firewall-Blocklisten nutzbar.**

![IPv4](https://img.shields.io/badge/IPv4-THREAT%20INTELLIGENCE-2563EB?style=flat-square)
![Scoring](https://img.shields.io/badge/CONFIDENCE-SCORING-7C3AED?style=flat-square)
![Discovery](https://img.shields.io/badge/AUTO-DISCOVERY-00A7E1?style=flat-square)
![Firewall](https://img.shields.io/badge/FIREWALL-READY-16A34A?style=flat-square)

`<br>`{=html}

[**⚡ Quick Start**](#-quick-start--opnsense-alias)   •   [**📊
Blocklisten**](#-blocklisten)   •   [**🎯
Scoring**](#-wie-funktioniert-die-bewertung)   •   [**🏗️
Architektur**](#%EF%B8%8F-architektur)   •   [**⚙️
Workflows**](#%EF%B8%8F-workflows)   •   [**📡 Feeds**](#-feed-quellen)
:::

```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

::: {align="center"}
## 📊 LIVE THREAT DASHBOARD

**Aktueller Zustand des NETSHIELD Threat-Intelligence-Netzes**

![Sources](https://img.shields.io/badge/IP--QUELLEN-286-00A7E1?style=for-the-badge)
![Active](https://img.shields.io/badge/AKTIVE%20BEDROHUNGEN-722%2C444-7C3AED?style=for-the-badge)
![CVE](https://img.shields.io/badge/CVE%20%2F%20EXPLOIT-29%2C367-F97316?style=for-the-badge)
![Honeypot](https://img.shields.io/badge/HONEYPOT-1%2C162%2C180-16A34A?style=for-the-badge)
:::

> \[!TIP\] **Live-Daten:** Die Tabellen direkt darunter werden weiterhin
> automatisch durch NETSHIELD aktualisiert.

```{=html}
<!-- STATS_TABLE_START -->
```
```{=html}
<table>
```
```{=html}
<tr>
```
```{=html}
<td align="center" valign="top" width="25%">
```
```{=html}
<h3>
```
286
```{=html}
</h3>
```
`<sub>`{=html}IP-Quellen`<br>`{=html}(dynamisch)`</sub>`{=html}
```{=html}
</td>
```
```{=html}
<td align="center" valign="top" width="25%">
```
```{=html}
<h3>
```
722,444
```{=html}
</h3>
```
`<sub>`{=html}Aktive IP-Drohungen`<br>`{=html}(Confidence
≥65)`</sub>`{=html}
```{=html}
</td>
```
```{=html}
<td align="center" valign="top" width="25%">
```
```{=html}
<h3>
```
29,367
```{=html}
</h3>
```
`<sub>`{=html}CVE/Exploit IPs`<br>`{=html} `</sub>`{=html}
```{=html}
</td>
```
```{=html}
<td align="center" valign="top" width="25%">
```
```{=html}
<h3>
```
1,162,180
```{=html}
</h3>
```
`<sub>`{=html}Honeypot IPs`<br>`{=html} `</sub>`{=html}
```{=html}
</td>
```
```{=html}
</tr>
```
```{=html}
</table>
```
```{=html}
<!-- STATS_TABLE_END -->
```
```{=html}
<!-- META_TABLE_START -->
```
```{=html}
<table>
```
```{=html}
<tr>
```
```{=html}
<td>
```
`<strong>`{=html}🕒 Letztes Update`</strong>`{=html}
```{=html}
</td>
```
```{=html}
<td>
```
2026-08-09 12:39 CEST (Europe/Berlin)
```{=html}
</td>
```
```{=html}
<td>
```
`<strong>`{=html}🔄 Intervall`</strong>`{=html}
```{=html}
</td>
```
```{=html}
<td>
```
8× täglich
```{=html}
</td>
```
```{=html}
</tr>
```
```{=html}
<tr>
```
```{=html}
<td>
```
`<strong>`{=html}📅 IP-Retention`</strong>`{=html}
```{=html}
</td>
```
```{=html}
<td>
```
180 Tage
```{=html}
</td>
```
```{=html}
<td>
```
`<strong>`{=html}⚙️ Aktive Workflows`</strong>`{=html}
```{=html}
</td>
```
```{=html}
<td>
```
26
```{=html}
</td>
```
```{=html}
</tr>
```
```{=html}
<tr>
```
```{=html}
<td>
```
`<strong>`{=html}🌍 Abdeckung`</strong>`{=html}
```{=html}
</td>
```
```{=html}
<td colspan="3">
```
250+ Länder
```{=html}
</td>
```
```{=html}
</tr>
```
```{=html}
</table>
```
```{=html}
<!-- META_TABLE_END -->
```
> NETSHIELD aggregiert, bewertet und bereinigt täglich
> IP-Bedrohungsdaten aus **über 160 Quellen** (dynamisch, wächst laufend
> durch Auto-Discovery): rund 120 öffentliche Remote-Feeds, 6 lokale
> Sub-Workflow-Feeds (CVE, Honeypot, Honigtopf, Bot-Detector, TweetFeed
> und laufend neu per GitHub-Discovery entdeckte Feeds. Das System
> unterscheidet aktive Bedrohungen von veralteten statischen Listen und
> liefert daraus qualitativ hochwertige Blocklisten für OPNsense,
> pfSense und iptables.

```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

## 🛡️ BLOCKLIST CENTER

> \[!IMPORTANT\] **Firewall-ready:** Hier liegen die produktiven
> NETSHIELD-Listen -- von direktem Blocking bis Audit/SIEM.

  -------------------------------------------------------------------------------------------------------------------------------------------
  Datei                                                                          Zweck                              Einträge Empfohlen für
  ------------------------------------------------------------------------------ --------------------- --------------------- ----------------
  🛡️ [`active_blacklist_ipv4.txt`](active_blacklist_ipv4.txt)                    Aktive Bedrohungen ·            **722,444** OPNsense /
                                                                                 letzte 30 Tage ·                            pfSense /
                                                                                 Score ≥ 65                                  Firewall

  🔶 [`_part1.txt`](blacklist_confidence40_ipv4_part1.txt) ·                     Mittleres bis hohes           **7,037,961** Erweiterte
  [`_part2.txt`](blacklist_confidence40_ipv4_part2.txt)                          Vertrauen · Score ≥                         Filterregeln
                                                                                 40 · 2 Parts                                

  📦 [`_part1.txt`](combined_threat_blacklist_ipv4_part1.txt) ·                  Alle IPs · 180 Tage ·         **8,775,160** Audit / SIEM
  [`_part2.txt`](combined_threat_blacklist_ipv4_part2.txt)                       2 Parts                                     

  👁️                                                                             Watchlist · Score                **44,636** Monitoring
  [`watchlist_confidence25to39_ipv4.txt`](watchlist_confidence25to39_ipv4.txt)   25--39                                      

  💣 [`cve_exploit_ips.txt`](cve_exploit_ips.txt)                                CVE-Exploits & aktive            **29,367** IDS / IPS
                                                                                 C2-Server                                   

  🍯 [`honeypot_ips.txt`](honeypot_ips.txt)                                      Honeypot-bestätigte           **1,162,180** Ergänzung
                                                                                 Angreifer                                   

  🍯 [`honigtopf_ips.txt`](honigtopf_ips.txt)                                    Honigtopf Community              **15,987** Ergänzung
                                                                                 Honeypot (API)                              

  🐦 [`tweetfeed_ips.txt`](tweetfeed_ips.txt)                                    TweetFeed.live                    **9,286** Ergänzung
                                                                                 Community IOCs                              

  🤖 [`bot_detector_blacklist_ipv4.txt`](bot_detector_blacklist_ipv4.txt)        Bot- & Scanner-IPs            **1,283,617** Web-Schutz

  🔗 [`reputation_blacklist.txt`](reputation_blacklist.txt)                      Reputation Top-IPs                **9,968** Ergänzung
                                                                                 (API, Score ≥50)                            
  -------------------------------------------------------------------------------------------------------------------------------------------

> \[!NOTE\] **Combined-Blacklist (2 feste Parts):** Die vollständige
> IPv4-Liste wird als genau zwei committete Dateien
> `combined_threat_blacklist_ipv4_part1.txt` und
> `combined_threat_blacklist_ipv4_part2.txt` bereitgestellt (IP-sortiert
> geteilt, je \~48 MB). Diese beiden Parts sind die **kanonische
> Quelle**. Die frühere Einzeldatei `combined_threat_blacklist_ipv4.txt`
> wird nicht mehr committet (sie würde das 100-MB-GitHub-Limit pro Datei
> sprengen); interne Workflows erzeugen sie bei Bedarf im Runner aus den
> Parts. Firewall-Konsumenten (z. B. OPNsense) importieren die beiden
> Part-URLs als separate Aliase. Hinweis: Bei fix zwei Parts liegt die
> harte Obergrenze bei \~200 MB gesamt (2 × 100-MB-Limit); ein
> Frühwarn-Log meldet, sobald ein Part 90 MB überschreitet.
>
> **Wann kommen keine neuen IPs mehr in die Hauptdatei?** Die Begrenzung
> erfolgt über die **Dateigröße**, nicht über eine feste IP-Anzahl.
> Solange die geschätzte Vollgröße unter 100 MB (`HARD_LIMIT_MB`)
> bleibt, enthält die Hauptdatei **alle** IPs. Sobald sie 100 MB
> erreichen würde, wird sie auf \~95 MB (`TRUNCATE_TARGET_MB`) gekürzt
> -- bei der aktuellen durchschnittlichen Zeilenlänge (\~14,3 Bytes/IP)
> entspricht das **rund 7 Millionen IPs**. Ab diesem Punkt wächst nur
> noch die Part-Datei-Reihe; zusätzliche IPs landen ausschließlich in
> den Parts. **Es gehen dabei keine IPs verloren** -- die Parts (und
> `seen_db`) enthalten stets die vollständige Liste. Die genaue Schwelle
> verschiebt sich leicht mit der IP-Zusammensetzung (kurze vs. lange
> Adressen).

```{=html}
<details>
```
```{=html}
<summary>
```
`<strong>`{=html}🌍 Geo-Listen`</strong>`{=html}
```{=html}
</summary>
```
    countries/              →  IPv4-Ranges pro Land, nach Kontinent sortiert
    continents/             →  Zusammengefasste Ranges pro Kontinent
    all_countries_ipv4.txt  →  Alle Länder in einer Datei

```{=html}
</details>
```
```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

## 🎯 CONFIDENCE ENGINE

> \[!NOTE\] Jede IP wird nicht einfach nur gesammelt, sondern anhand von
> **Qualität, Aktualität, Persistenz und Alter** bewertet.

Jede IP bekommt einen **Confidence-Score (0--100)** aus vier
Dimensionen:

    Score = Quellen-Qualität (40) + Aktualität (30) + Persistenz (20) + Bekannt seit (10)

  ------------------------------------------------------------------------
  Dimension                     **Gewicht**            Logik
  ------------------- -------------------------------- -------------------
  🏅 Quellen-Qualität               `40`               HQ-Feed = 40 · 5+
                                                       Feeds heute = 35 ·
                                                       3+ heute = 28 · 2+
                                                       heute = 20 · 5+
                                                       gesamt = 15 · 3+
                                                       gesamt = 10 · 2+
                                                       gesamt = 5

  ⏱️ Aktualität                     `30`               Heute = 30 · ≤ 3
                                                       Tage = 25 · ≤ 7
                                                       Tage = 20 · ≤ 14
                                                       Tage = 12 · ≤ 30
                                                       Tage = 6

  🔁 Persistenz                     `20`               14+ Tage = 20 · 7
                                                       Tage = 15 · 3 Tage
                                                       = 10 · 2 Tage = 6 ·
                                                       1 Tag = 2

  📆 Bekannt seit                   `10`               90+ Tage = 10 · 30+
                                                       Tage = 6 · 14+ Tage
                                                       = 3
  ------------------------------------------------------------------------

> \[!IMPORTANT\] Nur **HQ-Feeds** (Feodo, AbuseIPDB, Spamhaus,
> DataPlane, FireHOL u. a.) bestimmen die Lebenszeit einer IP. Statische
> Mega-Listen erhöhen den Score, können eine IP aber nicht am Leben
> halten. Nach **180 Tagen** ohne HQ-Bestätigung wird eine IP
> automatisch entfernt. Watchlist-IPs ohne HQ-Bestätigung laufen bereits
> nach **30 Tagen** ab.

### 🚦 Score-Zonen

       Score      Liste                Verwendung
  --------------- -------------------- ------------------------------
    🔴 **≥ 65**   `active_blacklist`   Firewall · direktes Blocking
    🟠 **≥ 40**   `confidence40`       Erweiterte Regeln
   🟡 **25--39**  `watchlist`          Nur Monitoring
   ⚪ **\< 25**   `combined`           Audit / SIEM

```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

## 🏗️ SYSTEM ARCHITEKTUR

> \[!TIP\] **Pipeline-Prinzip:** Quellen → Validierung → Confidence →
> Retention → spezialisierte Ausgabelisten.

    ~120 Quellen · dynamisch (Remote + Lokal + Auto-Discovered)
            │
            ▼
    ┌─────────────────────────────────────────────┐
    │         Update Combined Blacklist           │  ← Haupt-Engine · 8× täglich
    │                                             │
    │  ┌─────────────┐  ┌──────────────────────┐  │
    │  │  seen_db    │  │ False-Positive-Set   │  │
    │  │  (Cache)    │  │ (Whitelist-Filter)   │  │
    │  └──────┬──────┘  └──────────────────────┘  │
    │         │                                   │
    │   Score-Berechnung · HQ/Non-HQ Trennung     │
    │   IP-Lebenszeit: 180T (HQ) / 30T (Watchlist)│
    └──────────┬──────────────────────────────────┘
               │
         ┌─────┼─────────────────┐
         ▼     ▼                 ▼
      active  combined      confidence40
      ≥65     180T          ≥40 / watchlist
        │       │                │
        ▼       ▼                ▼
     OPNsense  Audit/SIEM    Analyse

    Sub-Workflows (vor Combined):
      CVE Mapper ──────┐
      Honeypot Monitor ├──→ Lokale .txt-Dateien ──→ Combined liest ein
      Honigtopf        │
      Bot-Detector ────┘

    Enrichment (nach Combined):
      Score Decay ─────→ Alterungs-Report (read-only)

```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

## ⚙️ AUTOMATION CONTROL

::: {align="center"}
![Automation](https://img.shields.io/badge/AUTOMATION-26%20WORKFLOWS-2563EB?style=for-the-badge&logo=githubactions&logoColor=white)
![Cycle](https://img.shields.io/badge/CORE%20CYCLE-8×%20DAILY-00A7E1?style=for-the-badge)
![Retention](https://img.shields.io/badge/RETENTION-180%20DAYS-7C3AED?style=for-the-badge)
![Coverage](https://img.shields.io/badge/COVERAGE-250%2B%20COUNTRIES-16A34A?style=for-the-badge)
:::

```{=html}
<details open>
```
```{=html}
<summary>
```
`<strong>`{=html}🔧 Kern-Pipeline`</strong>`{=html}
```{=html}
</summary>
```
  --------------------------------------------------------------------------
  Workflow                Zeitplan                Aufgabe
  ----------------------- ----------------------- --------------------------
  **Update Combined       8× täglich, alle 3h     Feeds laden, seen_db
  Blacklist**             (00:07, 03:07 ... 21:07 aktualisieren, combined +
                          UTC; +Backups :27/:47)  active Blacklists
                                                  schreiben

  **Confidence            8× täglich (01:47,      confidence40 + watchlist
  Blacklist**             04:47 ... 22:47 UTC)    aus seen_db berechnen

  **False Positive        3× täglich (05:00,      Whitelist-CIDRs prüfen →
  Checker**               13:00, 20:00 UTC)       false_positives_set.json

  **NETSHIELD Report      stündlich (:30)         NETSHIELD_REPORT.md +
  Generator**                                     README-Statistiken
                                                  aktualisieren
  --------------------------------------------------------------------------

```{=html}
</details>
```
```{=html}
<details>
```
```{=html}
<summary>
```
`<strong>`{=html}📡 Datenquellen (Sub-Workflows)`</strong>`{=html}
```{=html}
</summary>
```
  ---------------------------------------------------------------------------------
  Workflow                Zeitplan                Aufgabe
  ----------------------- ----------------------- ---------------------------------
  **CVE-to-IP Mapper**    täglich 04:00           C2/Exploit-IPs →
                                                  cve_exploit_ips.txt

  **Honeypot Monitor**    4× täglich (05:00,      Honeypot-Feeds → honeypot_ips.txt
                          11:00, 17:00, 23:00)    

  **Honigtopf**           stündlich (:15)         Honigtopf API → honigtopf_ips.txt

  **TweetFeed Monitor**   täglich 02:45           TweetFeed.live IOCs →
                                                  tweetfeed_ips.txt

  **Bot-Detector          täglich 22:45           Bot-IPs →
  Blacklist**                                     bot_detector_blacklist_ipv4.txt

  **Auto Feed Discovery** wöchentlich So 04:37    GitHub nach neuen Feeds
                          (+Backups 07:23, 11:47) durchsuchen
  ---------------------------------------------------------------------------------

```{=html}
</details>
```
```{=html}
<details>
```
```{=html}
<summary>
```
`<strong>`{=html}🔍 Enrichment & Monitoring`</strong>`{=html}
```{=html}
</summary>
```
  ------------------------------------------------------------------------
  Workflow                Zeitplan                Aufgabe
  ----------------------- ----------------------- ------------------------
  **Score Decay Monitor** wöchentlich So 07:00    Alterungs-Report
                                                  (read-only)

  **Feed Health Monitor** täglich 01:00           Feed-URLs auf
                                                  Erreichbarkeit prüfen

  **Workflow Health       4× täglich (01:15,      Python-Code + Production
  Checker**               07:15, 13:15, 19:15)    Health Checks (seen_db,
                                                  Output-Sanity, Drift,
                                                  Feed-Ausfälle)

  **Workflow Health       alle 6h (00:05, 06:05,  Workflow-Status-Report
  Report**                12:05, 18:05)           schreiben

  **Watchdog Combined**   alle 15 min             Combined-Pipeline auf
                                                  Stillstand überwachen

  **Watchdog Honigtopf**  4× pro Stunde           Honigtopf-Workflow auf
                          (:07/:22/:37/:52)       Stillstand überwachen

  **CodeQL Security       wöchentlich So 03:00    Statische
  Scan**                                          Sicherheitsanalyse des
                                                  Codes

  **Update All Countries  Mo + Mi 01:30           Länder/Kontinente
  IPv4**                                          IPv4-Ranges
                                                  synchronisieren
  ------------------------------------------------------------------------

```{=html}
</details>
```
```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

## 🕐 DATAFLOW & TIMING

> \[!NOTE\] Die folgenden Slots zeigen, wann Monitoring, Enrichment und
> die Kern-Pipeline ineinandergreifen.

    ── Häufig / stündlich (UTC) ───────────────────────────────────
    */15              Watchdog Combined            (Stillstands-Check)
    :07/:22/:37/:52   Watchdog Honigtopf           (Stillstands-Check)
    :15               Honigtopf  ──────────────────┐  (stündlich)
    :30               NETSHIELD Report Generator   │  (stündlich)
                                                   │
    ── Combined-Pipeline · 8× täglich, alle 3h ────┤
    00:07,03:07 … 21:07  Update Combined Blacklist ┼──→ seen_db Cache
                         (+Backups :27 / :47)      │
    01:47,04:47 … 22:47  Confidence Blacklist ─────┘  (8× täglich)

    ── Täglich · feste Slots (UTC) ────────────────────────────────
    00:05,06:05,12:05,18:05  Workflow Health Report
    01:00             Feed Health Monitor
    01:15,07:15,13:15,19:15  Workflow Health Checker
    01:30 (Mo+Mi)     Update All Countries
    02:45             TweetFeed Monitor
    03:00 (So)        CodeQL Security Scan
    04:00             CVE-to-IP Mapper
    04:37 (So)        Auto Feed Discovery (+Backups 07:23, 11:47)
    05:00,11:00,17:00,23:00  Honeypot Monitor
    05:00,13:00,20:00        False Positive Checker
    07:00 (So)        Score Decay Monitor
    22:45             Bot-Detector Blacklist

```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

## 📈 REPORTING & MONITORING

> \[!TIP\] Reports machen Feed-Zustand, Workflow-Gesundheit, Alterung
> und Discovery transparent.

  ------------------------------------------------------------------------------------------------------------------
  Datei                                                                          Inhalt
  ------------------------------------------------------------------------------ -----------------------------------
  📊 [`NETSHIELD_REPORT.md`](NETSHIELD_REPORT.md)                                Gesamtübersicht + Feed Health (alle
                                                                                 30 min)

  💚 [`feed_health_report.md`](feed_health_report.md)                            Status aller Feed-URLs

  ⚙️ [`workflow_health_report.md`](workflow_health_report.md)                    Workflow-Analyse (Python-Syntax,
                                                                                 Cron-Timing, Guards)

  🔀                                                                             Feed-Statistik pro Lauf
  [`combined_threat_blacklist_report.md`](combined_threat_blacklist_report.md)   

  📉 [`score_decay_report.md`](score_decay_report.md)                            Alterungs-Analyse der seen_db

  🔎 [`auto_feed_discovery_report.md`](auto_feed_discovery_report.md)            Neu entdeckte Feeds + Bewertung
  ------------------------------------------------------------------------------------------------------------------

```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

## 📡 INTELLIGENCE SOURCES

> \[!IMPORTANT\] NETSHIELD kombiniert kuratierte HQ-Feeds mit Community-
> und Auto-Discovery-Quellen.

NETSHIELD bezieht Daten aus folgenden Kategorien:

  ------------------------------------------------------------------------------
  Kategorie                Beispiele                           HQ
  ------------------------ -------------------- --------------------------------
  Abuse-Tracker            Feodo, ThreatFox,                   ✅
                           URLhaus (abuse.ch)   

  Blocklist-Aggregatoren   FireHOL Level 1--4,                 ✅
                           blocklist.de,        
                           DShield              

  Honeypot-Netzwerke       DataPlane, Turris                   ✅
                           Sentinel, Honigtopf  
                           (API)                

  Reputation-Feeds         AbuseIPDB (API +                    ✅
                           Mirrors), ipsum,     
                           CINSscore            

  C2/Botnet-Tracker        C2-Tracker, MISP C2                 ✅
                           Intel Feeds          

  Threat Intelligence      Spamhaus DROP,                      ✅
                           Emerging Threats,    
                           Threatview           

  Community-Feeds          GitHub-Repos                        ❌
                           (auto-discovered),   
                           Bot-Detector         

  Brute-Force-Listen       CrowdSec,                           ✅
                           danger.rulez.sk,     
                           blocklist.de/ssh     
  ------------------------------------------------------------------------------

> \[!IMPORTANT\] **HQ-Feeds** (rund die Hälfte aller Remote-Quellen)
> bestimmen die Lebenszeit einer IP. Non-HQ-Feeds erhöhen den
> Confidence-Score, können IPs aber nicht am Leben halten.

```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

## 📁 REPOSITORY MAP

```{=html}
<details>
```
```{=html}
<summary>
```
`<strong>`{=html}Repository-Layout anzeigen`</strong>`{=html}
```{=html}
</summary>
```
    NETSHIELD/
    ├── .github/workflows/                   # GitHub Actions Workflows
    ├── continents/                          # IPv4-Ranges pro Kontinent
    ├── countries/                           # IPv4-Ranges pro Land
    │   ├── africa/ · asia/ · europe/
    │   ├── north_america/ · oceania/ · south_america/
    │
    ├── active_blacklist_ipv4.txt            # → Firewall (Score ≥65, 30 Tage)
    ├── blacklist_confidence40_ipv4_part1.txt  # → Erweiterte Regeln (Score ≥40) – kanonisch, Teil 1/2
    ├── blacklist_confidence40_ipv4_part2.txt  #   kanonisch, Teil 2/2 (Einzeldatei nicht mehr committet)
    ├── combined_threat_blacklist_ipv4_part1.txt  # → Audit / SIEM (180 Tage) – kanonisch, Teil 1/2
    ├── combined_threat_blacklist_ipv4_part2.txt  #   kanonisch, Teil 2/2 (Einzeldatei nicht mehr committet)
    ├── watchlist_confidence25to39_ipv4.txt  # → Monitoring (Score 25–39)
    │
    ├── cve_exploit_ips.txt                  # CVE/C2-IPs (täglich)
    ├── honeypot_ips.txt                     # Honeypot-Feeds (täglich)
    ├── honigtopf_ips.txt                    # Honigtopf API (täglich)
    ├── tweetfeed_ips.txt                    # TweetFeed.live IOCs (täglich)
    ├── bot_detector_blacklist_ipv4.txt      # Bot-Detector (täglich)
    ├── reputation_blacklist.txt          # Reputation API (Round-Robin)
    │
    ├── auto_discovered_feeds.json           # Auto-entdeckte Feeds
    ├── false_positives_set.json             # FP-Whitelist
    ├── feed_health_status.json              # Feed-Status
    ├── seen_db_meta.json                    # seen_db Metadaten (DB im Cache)
    │
    ├── NETSHIELD_REPORT.md                  # Haupt-Dashboard
    └── README.md

```{=html}
</details>
```
```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

## 🔒 SAFETY & RESILIENCE

::: {align="center"}
![Empty
Guard](https://img.shields.io/badge/EMPTY%20GUARD-ACTIVE-16A34A?style=flat-square)
![FP
Filter](https://img.shields.io/badge/FALSE%20POSITIVE-FILTERED-00A7E1?style=flat-square)
![Retry](https://img.shields.io/badge/PUSH%20RETRY-5×-F97316?style=flat-square)
![Lock](https://img.shields.io/badge/CONCURRENCY-LOCKED-7C3AED?style=flat-square)
:::

  -----------------------------------------------------------------------
  Mechanismus                         Beschreibung
  ----------------------------------- -----------------------------------
  🛑 **Leerungsschutz**               Jeder Workflow prüft MIN_ENTRIES
                                      vor dem Schreiben --- bei zu
                                      wenigen Ergebnissen bleibt die alte
                                      Datei erhalten

  ⚪ **False-Positive-Filter**        Umfangreiche Whitelist (CDN, DNS,
                                      Mail, Cloud-Provider) verhindert
                                      Blocking legitimer Infrastruktur

  🏅 **HQ/Non-HQ-Trennung**           Nur verifizierte HQ-Feeds
                                      verlängern die Lebenszeit einer IP
                                      --- statische Listen können IPs
                                      nicht am Leben halten

  🔁 **Push-Retry**                   5 Versuche mit git rebase bei
                                      gleichzeitigen Commits

  🔐 **Concurrency-Lock**             Jeder Workflow läuft max. 1×
                                      gleichzeitig

  📦 **Cache-Isolation**              Verschiedene Workflows nutzen
                                      eigene Cache-Prefixe (v2, fp, afd)
  -----------------------------------------------------------------------

```{=html}
<p align="center">
```
🔹 `<b>`{=html}NETSHIELD`</b>`{=html} 🔹
```{=html}
</p>
```

------------------------------------------------------------------------

::: {align="center"}
### 🛡️ NETSHIELD

**Automated Threat Intelligence · Confidence Scoring · Firewall
Blocklists**

![Status](https://img.shields.io/badge/STATUS-AUTOMATED-16A34A?style=for-the-badge)
![Defense](https://img.shields.io/badge/DEFENSE-ACTIVE-2563EB?style=for-the-badge)

`<sub>`{=html}*Automatisch aktualisiert ·
[NETSHIELD_REPORT.md](NETSHIELD_REPORT.md)*`</sub>`{=html}

**[⬆ Nach oben](#-netshield)**
:::
