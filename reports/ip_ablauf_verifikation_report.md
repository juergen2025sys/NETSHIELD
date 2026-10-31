# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-31 02:17 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 2776 |
| Active (180-Tage-Pfad) | 3594920 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-31 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-01 | 2,000 | 0 | 0% |
| 2026-11-02 | 2,000 | 0 | 0% |
| 2026-11-03 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-31 (heute) | 87,983 | 87,983 | 87,983 | regulaerer Tagesstand |
| 2026-11-01 | 27,683 | 0 | – | noch nicht faellig |
| 2026-11-02 | 28,623 | 0 | – | noch nicht faellig |
| 2026-11-03 | 29,563 | 0 | – | noch nicht faellig |

**Active heute:** 87,983 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 87,983 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

❌ **1 Problem(e) erkannt:**

- ❌ **Rückfall:** 87983 eingefrorene IP(s) stehen trotzdem in aktuellen Output-Dateien - der Anti-Churn-Fix greift hier NICHT wie erwartet.

## Wiederauftauch-Prüfung

ℹ️ **2,114 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,871,771 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-31). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

❌ **87983 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen - der Fix greift hier NICHT wie erwartet (Issue-Alarm ausgeloest, Schwelle 300):**

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| blacklist_confidence40_ipv4_part1.txt | 63820 | 1.0.149.227, 1.0.211.34, 1.1.140.164, 1.1.230.7, 1.1.251.105, ... |
| blacklist_confidence40_ipv4_part2.txt | 24163 | 222.75.165.169, 222.75.165.215, 222.75.166.209, 222.75.166.223, 222.75.166.233, ... |

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-17 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-18 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-19 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-20 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-21 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-22 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-23 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-24 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-25 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-26 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-27 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-28 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-29 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-30 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-17 | 24,149 | 24,147 | 2 | 0.0% |
| 2026-10-18 | 14,154 | 14,152 | 2 | 0.0% |
| 2026-10-19 | 21,951 | 21,944 | 7 | 0.0% |
| 2026-10-20 | 11,053 | 11,052 | 1 | 0.0% |
| 2026-10-21 | 11,006 | 11,003 | 3 | 0.0% |
| 2026-10-22 | 30,437 | 30,435 | 2 | 0.0% |
| 2026-10-23 | 50,171 | 50,169 | 2 | 0.0% |
| 2026-10-24 | 41,537 | 41,533 | 4 | 0.0% |
| 2026-10-25 | 21,450 | 21,449 | 1 | 0.0% |
| 2026-10-26 | 20,152 | 20,148 | 4 | 0.0% |
| 2026-10-27 | 20,360 | 20,356 | 4 | 0.0% |
| 2026-10-28 | 15,457 | 15,453 | 4 | 0.0% |
| 2026-10-29 | 9,468 | 9,465 | 3 | 0.0% |
| 2026-10-30 | 61,481 | 61,477 | 4 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📉 -86,938 (Rückgang) (jetzt 11,144,718 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +86,275 (Anstieg)
- Letzter combined-Cleanup-Pass: 89,983 IPs durch Ablauf entfernt (davon 2,000 Watchlist/30T, 87,983 Active/180T), 866,944 neue IPs hinzugekommen (davon 744,259 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 18 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 119,960 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 6,968,860 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 216,943 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 6,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 210,943 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📉 -49,065 (~24h) ⚠️ **schrumpft aktuell netto** - mehr entfernt als neu aufgenommen
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-29T22:58 bis 2026-10-31T01:03 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-28 14:30 CET (Europe/Berlin) | 11,199,494 | 8776 | 3436684 | 0 |
| 2026-10-28 14:41 CET (Europe/Berlin) | 11,199,494 | 8776 | 3436684 | 0 |
| 2026-10-28 20:08 CET (Europe/Berlin) | 11,205,466 | 8776 | 3436581 | 0 |
| 2026-10-28 21:42 CET (Europe/Berlin) | 11,208,279 | 8776 | 3436557 | 0 |
| 2026-10-29 00:32 CET (Europe/Berlin) | 11,210,120 | 8776 | 3436540 | 0 |
| 2026-10-29 02:27 CET (Europe/Berlin) | 11,201,048 | 6776 | 3445983 | 0 |
| 2026-10-29 10:48 CET (Europe/Berlin) | 11,214,240 | 6776 | 3445913 | 0 |
| 2026-10-29 11:37 CET (Europe/Berlin) | 11,216,567 | 6776 | 3445873 | 0 |
| 2026-10-29 17:54 CET (Europe/Berlin) | 11,234,102 | 6776 | 3445821 | 0 |
| 2026-10-29 19:45 CET (Europe/Berlin) | 11,236,310 | 6776 | 3445777 | 0 |
| 2026-10-29 22:48 CET (Europe/Berlin) | 11,237,937 | 6776 | 3445766 | 0 |
| 2026-10-30 00:03 CET (Europe/Berlin) | 11,254,564 | 6776 | 3445722 | 0 |
| 2026-10-30 02:52 CET (Europe/Berlin) | 11,193,783 | 4776 | 3507176 | 0 |
| 2026-10-30 07:40 CET (Europe/Berlin) | 11,193,783 | 4776 | 3507176 | 0 |
| 2026-10-30 09:32 CET (Europe/Berlin) | 11,204,068 | 4776 | 3507144 | 0 |
| 2026-10-30 14:44 CET (Europe/Berlin) | 11,215,479 | 4776 | 3507093 | 0 |
| 2026-10-30 21:08 CET (Europe/Berlin) | 11,225,818 | 4776 | 3506999 | 0 |
| 2026-10-30 21:18 CET (Europe/Berlin) | 11,225,818 | 4776 | 3506999 | 0 |
| 2026-10-31 01:03 CET (Europe/Berlin) | 11,231,656 | 4776 | 3506971 | 0 |
| 2026-10-31 02:17 CET (Europe/Berlin) | 11,144,718 | 2776 | 3594920 | 87983 |
