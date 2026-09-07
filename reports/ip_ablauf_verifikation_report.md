# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-07 21:30 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 186480 |
| Active (180-Tage-Pfad) | 173616 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt jetzt die TATSAECHLICH an diesem Kalendertag vom Combined-Lauf entfernten IPs (`expired_watchlist` bzw. `expired_active`). Damit werden Watchlist-Rueckstaende durch den 2.000/Tag-Deckel korrekt dem realen Entfernungstag zugerechnet. Dieselbe Ist-Logik gilt fuer Active/180T, damit auch verspaetete Cleanup-Laeufe nicht dem theoretischen Faelligkeitsdatum zugeschrieben werden.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-07 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-08 | 2,000 | 0 | 0% |
| 2026-09-09 | 2,000 | 0 | 0% |
| 2026-09-10 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-07 (heute) | 663,981 | 777,092 | 117% |
| 2026-09-08 | 662,390 | 0 | 0% |
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 6,476 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **267 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **346 Treffer sind legitime Watchlist→Active-Aufstiege und kein Anti-Churn-Rückfall.** Diese IPs stehen im Watchlist-Ledger, wurden aber per echter Zweitbestätigung (2+ HQ-Familien) direkt in den Active-Pfad aufgenommen und stehen deshalb in `active_blacklist_ipv4.txt`, ohne (noch) im Active-Ledger zu stehen. Spiegelbild des Active→Watchlist-Falls oben.

ℹ️ **176,535 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 448,736 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-07). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 267 legitime Active→Watchlist-Treffer; 346 legitime Watchlist→Active-Treffer; 176,535 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-08-30 | 10,066 | 0 | 10,066 | 100.0% |
| 2026-08-31 | 5,240 | 9,838 | 0 | 0.0% |
| 2026-09-01 | 52,949 | 0 | 52,949 | 100.0% |
| 2026-09-02 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-03 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-04 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-05 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-06 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-06 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |

_49 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +23,482 (Anstieg) (jetzt 11,214,280 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,818,241 (Anstieg)
- Letzter combined-Cleanup-Pass: 155,446 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 155,446 Active/180T), 1,029,027 neue IPs hinzugekommen (davon 830,036 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 395 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 189,676 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,063,644 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,245,348 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 1,243,348 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +56,131 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-06T22:56 bis 2026-09-07T19:22 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-05 22:43 CEST (Europe/Berlin) | 11,053,966 | 186482 | 173654 | 259 |
| 2026-09-05 22:50 CEST (Europe/Berlin) | 11,053,966 | 186482 | 173654 | 259 |
| 2026-09-06 00:49 CEST (Europe/Berlin) | 11,101,732 | 186482 | 173637 | 270 |
| 2026-09-06 01:28 CEST (Europe/Berlin) | 11,101,732 | 186482 | 173637 | 270 |
| 2026-09-06 07:21 CEST (Europe/Berlin) | 11,112,408 | 186482 | 173637 | 275 |
| 2026-09-06 12:48 CEST (Europe/Berlin) | 11,118,199 | 186481 | 173637 | 277 |
| 2026-09-06 13:27 CEST (Europe/Berlin) | 11,118,199 | 186481 | 173637 | 277 |
| 2026-09-06 16:08 CEST (Europe/Berlin) | 11,124,841 | 186481 | 173633 | 289 |
| 2026-09-06 17:55 CEST (Europe/Berlin) | 11,130,332 | 186481 | 173632 | 292 |
| 2026-09-06 20:09 CEST (Europe/Berlin) | 11,128,881 | 186481 | 173632 | 292 |
| 2026-09-06 21:30 CEST (Europe/Berlin) | 11,150,438 | 186481 | 173626 | 295 |
| 2026-09-06 22:58 CEST (Europe/Berlin) | 11,155,666 | 186481 | 173624 | 300 |
| 2026-09-07 01:22 CEST (Europe/Berlin) | 11,158,149 | 186481 | 173624 | 301 |
| 2026-09-07 01:47 CEST (Europe/Berlin) | 11,158,149 | 186481 | 173624 | 301 |
| 2026-09-07 06:19 CEST (Europe/Berlin) | 11,163,016 | 186481 | 173619 | 308 |
| 2026-09-07 07:30 CEST (Europe/Berlin) | 11,170,094 | 186480 | 173619 | 311 |
| 2026-09-07 11:42 CEST (Europe/Berlin) | 11,171,671 | 186480 | 173619 | 316 |
| 2026-09-07 15:11 CEST (Europe/Berlin) | 11,190,798 | 186480 | 173619 | 334 |
| 2026-09-07 17:07 CEST (Europe/Berlin) | 11,190,798 | 186480 | 173619 | 0 |
| 2026-09-07 21:30 CEST (Europe/Berlin) | 11,214,280 | 186480 | 173616 | 0 |
