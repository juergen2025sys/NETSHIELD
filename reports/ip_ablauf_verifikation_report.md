# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-25 22:20 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 14778 |
| Active (180-Tage-Pfad) | 3381679 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-25 (heute) | 2,000 | 2,000 | 100% |
| 2026-10-26 | 2,000 | 0 | 0% |
| 2026-10-27 | 2,000 | 0 | 0% |
| 2026-10-28 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-25 (heute) | 21,450 | 21,450 | 0 | regulaerer Tagesstand |
| 2026-10-26 | 20,152 | 0 | – | noch nicht faellig |
| 2026-10-27 | 20,367 | 0 | – | noch nicht faellig |
| 2026-10-28 | 15,471 | 0 | – | noch nicht faellig |

**Active heute:** 21,450 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **2,127 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,770,799 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-25). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 2,127 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-11 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-12 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-13 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-14 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-15 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-16 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-17 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-18 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-19 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-20 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-21 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-22 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-23 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-24 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-11 | 15,987 | 15,987 | 0 | 0.0% |
| 2026-10-12 | 66,480 | 66,477 | 3 | 0.0% |
| 2026-10-13 | 1,579,746 | 1,579,622 | 124 | 0.0% |
| 2026-10-14 | 32,901 | 32,898 | 3 | 0.0% |
| 2026-10-15 | 41,267 | 41,263 | 4 | 0.0% |
| 2026-10-16 | 51,126 | 51,121 | 5 | 0.0% |
| 2026-10-17 | 24,149 | 24,147 | 2 | 0.0% |
| 2026-10-18 | 14,154 | 14,152 | 2 | 0.0% |
| 2026-10-19 | 21,951 | 21,944 | 7 | 0.0% |
| 2026-10-20 | 11,053 | 11,052 | 1 | 0.0% |
| 2026-10-21 | 11,006 | 11,003 | 3 | 0.0% |
| 2026-10-22 | 30,437 | 30,435 | 2 | 0.0% |
| 2026-10-23 | 50,171 | 50,169 | 2 | 0.0% |
| 2026-10-24 | 41,537 | 41,533 | 4 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 11,164,227 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +105,784 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 806,274 neue IPs hinzugekommen (davon 745,090 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 10 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 2 Whitelist-Bereinigung, 60,481 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 6,554,864 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 23,450 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 21,450 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +43,123 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-25T00:30 bis 2026-10-25T21:14 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-23 21:58 CEST (Europe/Berlin) | 11,121,403 | 18782 | 3319272 | 0 |
| 2026-10-23 23:47 CEST (Europe/Berlin) | 11,125,793 | 18782 | 3319248 | 0 |
| 2026-10-24 01:05 CEST (Europe/Berlin) | 11,125,793 | 18782 | 3319248 | 0 |
| 2026-10-24 02:10 CEST (Europe/Berlin) | 11,125,793 | 18782 | 3319248 | 0 |
| 2026-10-24 03:58 CEST (Europe/Berlin) | 11,091,073 | 16782 | 3360755 | 0 |
| 2026-10-24 07:15 CEST (Europe/Berlin) | 11,100,673 | 16782 | 3360729 | 0 |
| 2026-10-24 13:44 CEST (Europe/Berlin) | 11,115,691 | 16781 | 3360663 | 0 |
| 2026-10-24 18:20 CEST (Europe/Berlin) | 11,128,168 | 16781 | 3360589 | 0 |
| 2026-10-24 18:23 CEST (Europe/Berlin) | 11,128,168 | 16781 | 3360589 | 0 |
| 2026-10-24 23:20 CEST (Europe/Berlin) | 11,134,883 | 16781 | 3360554 | 0 |
| 2026-10-25 01:43 CEST (Europe/Berlin) | 11,142,480 | 16781 | 3360505 | 0 |
| 2026-10-25 01:53 CEST (Europe/Berlin) | 11,142,480 | 16781 | 3360505 | 0 |
| 2026-10-25 05:26 CET (Europe/Berlin) | 11,121,104 | 14781 | 3381940 | 0 |
| 2026-10-25 06:33 CET (Europe/Berlin) | 11,128,726 | 14780 | 3381917 | 0 |
| 2026-10-25 10:24 CET (Europe/Berlin) | 11,128,726 | 14780 | 3381917 | 0 |
| 2026-10-25 13:14 CET (Europe/Berlin) | 11,137,806 | 14780 | 3381840 | 0 |
| 2026-10-25 14:56 CET (Europe/Berlin) | 11,137,806 | 14780 | 3381840 | 0 |
| 2026-10-25 17:56 CET (Europe/Berlin) | 11,157,004 | 14779 | 3381754 | 0 |
| 2026-10-25 21:47 CET (Europe/Berlin) | 11,164,227 | 14778 | 3381679 | 0 |
| 2026-10-25 22:20 CET (Europe/Berlin) | 11,164,227 | 14778 | 3381679 | 0 |
