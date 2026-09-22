# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-22 02:27 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 3986 |
| Active (180-Tage-Pfad) | 837060 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-22 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-23 | 2,000 | 0 | 0% |
| 2026-09-24 | 2,000 | 0 | 0% |
| 2026-09-25 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-09-22 (heute) | 6,431 | 6,430 | 6,430 | regulaerer Tagesstand |
| 2026-09-23 | 13,054 | 0 | – | noch nicht faellig |
| 2026-09-24 | 16,662 | 0 | – | noch nicht faellig |
| 2026-09-25 | 20,927 | 0 | – | noch nicht faellig |

**Active heute:** 6,430 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 6,430 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

❌ **1 Problem(e) erkannt:**

- ❌ **Rückfall:** 6430 eingefrorene IP(s) stehen trotzdem in aktuellen Output-Dateien - der Anti-Churn-Fix greift hier NICHT wie erwartet.

## Wiederauftauch-Prüfung

ℹ️ **3,736 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 593,792 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-22). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

❌ **6430 IP(s) gefunden, die laut Ablauf-Liste dauerhaft draussen sein sollten, aber trotzdem in einer aktuellen Output-Datei stehen - der Fix greift hier NICHT wie erwartet (Issue-Alarm ausgeloest, Schwelle 300):**

| Datei | Anzahl Rückfälle | Beispiele |
|---|---:|---|
| blacklist_confidence40_ipv4_part2.txt | 6430 | 1.0.214.42, 1.10.240.249, 1.10.255.64, 1.159.189.158, 1.161.138.202, ... |

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-08 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-09 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-10 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-11 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-12 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-13 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-14 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-15 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-16 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-17 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-18 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-19 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-20 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-21 | 2,000 | 0 | 2,000 | 100.0% |

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |
| 2026-09-21 | 6,509 | 0 | 6,509 | 100.0% |

_60 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📉 -3,556 (Rückgang) (jetzt 11,477,719 IPs)
- Seit Zyklus-Start (2026-09-22): n/a (kein Vergleichswert)
- Letzter combined-Cleanup-Pass: 8,430 IPs durch Ablauf entfernt (davon 2,000 Watchlist/30T, 6,430 Active/180T), 962,643 neue IPs hinzugekommen (davon 829,320 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 94 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 128,694 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 962,643 (Summe letzte 1 Läufe / 1 Lauf(e), noch keine 24h Historie seit Zyklus-Start)
- Entfernte IPs (Summe letzter Läufe): 8,430 (Summe letzte 1 Läufe / 1 Lauf(e), noch keine 24h Historie seit Zyklus-Start)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 1 Läufe / 1 Lauf(e), noch keine 24h Historie seit Zyklus-Start)
  - davon Active/180 Tage: 6,430 (Summe letzte 1 Läufe / 1 Lauf(e), noch keine 24h Historie seit Zyklus-Start)
- Netto-Wachstum (1 Lauf(e), noch keine 24h Historie seit Zyklus-Start): ➡️ unverändert
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-21T05:30 bis 2026-09-22T00:17 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-22 02:27 CEST (Europe/Berlin) | 11,477,719 | 3986 | 837060 | 6430 |
