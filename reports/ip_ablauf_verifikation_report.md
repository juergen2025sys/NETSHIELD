# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-20 13:56 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 4225 |
| Active (180-Tage-Pfad) | 830929 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt jetzt die TATSAECHLICH an diesem Kalendertag vom Combined-Lauf entfernten IPs (`expired_watchlist` bzw. `expired_active`). Damit werden Watchlist-Rueckstaende durch den 2.000/Tag-Deckel korrekt dem realen Entfernungstag zugerechnet. Dieselbe Ist-Logik gilt fuer Active/180T, damit auch verspaetete Cleanup-Laeufe nicht dem theoretischen Faelligkeitsdatum zugeschrieben werden.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-20 (heute) | 2,000 | 0 | 0% |
| 2026-09-21 | 2,000 | 0 | 0% |
| 2026-09-22 | 2,000 | 0 | 0% |
| 2026-09-23 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 6,436 | 0 | 0% |
| 2026-09-23 | 13,064 | 0 | 0% |
| 2026-09-24 | 16,677 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **194,439 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **3,935 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 578,005 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-20). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 194,439 legitime Active→Watchlist-Treffer; 3,935 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-06 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-07 | 2,000 | 0 | 2,000 | 100.0% |
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

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |

_60 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 11,603,678 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +2,207,639 (Anstieg)
- Letzter combined-Cleanup-Pass: 243,532 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 243,532 Active/180T), 1,082,216 neue IPs hinzugekommen (davon 938,885 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 433 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 132,969 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,623,626 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,948,701 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 1,948,701 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +57,447 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-19T18:52 bis 2026-09-20T11:49 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-18 07:25 CEST (Europe/Berlin) | 11,434,033 | 4342 | 831542 | 0 |
| 2026-09-18 14:00 CEST (Europe/Berlin) | 11,461,407 | 4340 | 831421 | 0 |
| 2026-09-18 18:45 CEST (Europe/Berlin) | 11,473,877 | 4340 | 831382 | 0 |
| 2026-09-18 18:51 CEST (Europe/Berlin) | 11,473,877 | 4340 | 831382 | 0 |
| 2026-09-18 21:34 CEST (Europe/Berlin) | 11,483,918 | 4340 | 831364 | 0 |
| 2026-09-18 23:22 CEST (Europe/Berlin) | 11,485,563 | 4340 | 831358 | 0 |
| 2026-09-19 01:46 CEST (Europe/Berlin) | 11,494,200 | 4340 | 831350 | 0 |
| 2026-09-19 07:00 CEST (Europe/Berlin) | 11,508,382 | 4229 | 831299 | 0 |
| 2026-09-19 07:21 CEST (Europe/Berlin) | 11,508,382 | 4229 | 831299 | 0 |
| 2026-09-19 11:25 CEST (Europe/Berlin) | 11,527,431 | 4229 | 831266 | 0 |
| 2026-09-19 13:43 CEST (Europe/Berlin) | 11,537,242 | 4228 | 831238 | 0 |
| 2026-09-19 15:36 CEST (Europe/Berlin) | 11,542,682 | 4228 | 831165 | 0 |
| 2026-09-19 18:11 CEST (Europe/Berlin) | 11,546,231 | 4228 | 831152 | 0 |
| 2026-09-19 21:26 CEST (Europe/Berlin) | 11,560,330 | 4227 | 831075 | 0 |
| 2026-09-19 23:12 CEST (Europe/Berlin) | 11,563,888 | 4227 | 831066 | 0 |
| 2026-09-20 01:48 CEST (Europe/Berlin) | 11,570,463 | 4227 | 831052 | 0 |
| 2026-09-20 07:22 CEST (Europe/Berlin) | 11,584,609 | 4227 | 831001 | 0 |
| 2026-09-20 07:34 CEST (Europe/Berlin) | 11,584,609 | 4227 | 831001 | 0 |
| 2026-09-20 12:11 CEST (Europe/Berlin) | 11,603,678 | 4225 | 830929 | 0 |
| 2026-09-20 13:56 CEST (Europe/Berlin) | 11,603,678 | 4225 | 830929 | 0 |
