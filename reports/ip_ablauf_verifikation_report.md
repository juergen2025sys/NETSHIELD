# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-14 01:49 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 185243 |
| Active (180-Tage-Pfad) | 832986 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt jetzt die TATSAECHLICH an diesem Kalendertag vom Combined-Lauf entfernten IPs (`expired_watchlist` bzw. `expired_active`). Damit werden Watchlist-Rueckstaende durch den 2.000/Tag-Deckel korrekt dem realen Entfernungstag zugerechnet. Dieselbe Ist-Logik gilt fuer Active/180T, damit auch verspaetete Cleanup-Laeufe nicht dem theoretischen Faelligkeitsdatum zugeschrieben werden.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-14 (heute) | 2,000 | 0 | 0% |
| 2026-09-15 | 2,000 | 0 | 0% |
| 2026-09-16 | 2,000 | 0 | 0% |
| 2026-09-17 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 6,450 | 0 | 0% |
| 2026-09-23 | 13,104 | 0 | 0% |
| 2026-09-24 | 16,746 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **190,850 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **160 Treffer sind legitime Watchlist→Active-Aufstiege und kein Anti-Churn-Rückfall.** Diese IPs stehen im Watchlist-Ledger, wurden aber per echter Zweitbestätigung (2+ HQ-Familien) direkt in den Active-Pfad aufgenommen und stehen deshalb in `active_blacklist_ipv4.txt`, ohne (noch) im Active-Ledger zu stehen. Spiegelbild des Active→Watchlist-Falls oben.

ℹ️ **175,871 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 520,907 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-13). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 190,850 legitime Active→Watchlist-Treffer; 160 legitime Watchlist→Active-Treffer; 175,871 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-01 | 52,949 | 0 | 52,949 | 100.0% |
| 2026-09-02 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-03 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-04 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-05 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-06 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-06 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-07 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-08 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-09 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-10 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-11 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-12 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-13 | 2,000 | 0 | 2,000 | 100.0% |

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |

_53 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 11,106,292 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,710,253 (Anstieg)
- Letzter combined-Cleanup-Pass: 244,872 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 244,872 Active/180T), 1,073,557 neue IPs hinzugekommen (davon 935,968 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) (zusätzlich: 1 geschützt entfernt, 139,099 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,585,620 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,959,986 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 1,959,986 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +15,463 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | 1 sonstige, Zeitraum 2026-09-13T11:39 bis 2026-09-13T23:33 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-12 01:44 CEST (Europe/Berlin) | 11,009,397 | 186474 | 833826 | 0 |
| 2026-09-12 03:31 CEST (Europe/Berlin) | 11,010,142 | 186473 | 833779 | 0 |
| 2026-09-12 07:17 CEST (Europe/Berlin) | 11,021,303 | 186473 | 833764 | 0 |
| 2026-09-12 13:14 CEST (Europe/Berlin) | 11,044,348 | 186473 | 833482 | 0 |
| 2026-09-12 13:24 CEST (Europe/Berlin) | 11,044,348 | 186473 | 833482 | 0 |
| 2026-09-12 16:23 CEST (Europe/Berlin) | 11,055,868 | 186473 | 833414 | 0 |
| 2026-09-12 17:56 CEST (Europe/Berlin) | 11,057,581 | 186473 | 833385 | 0 |
| 2026-09-12 21:40 CEST (Europe/Berlin) | 11,061,542 | 186473 | 833329 | 0 |
| 2026-09-12 23:08 CEST (Europe/Berlin) | 11,065,480 | 185406 | 833327 | 0 |
| 2026-09-13 01:38 CEST (Europe/Berlin) | 11,069,423 | 185400 | 833287 | 0 |
| 2026-09-13 07:21 CEST (Europe/Berlin) | 11,084,039 | 185338 | 833229 | 0 |
| 2026-09-13 07:31 CEST (Europe/Berlin) | 11,084,039 | 185338 | 833229 | 0 |
| 2026-09-13 12:49 CEST (Europe/Berlin) | 11,090,829 | 185304 | 833161 | 0 |
| 2026-09-13 14:28 CEST (Europe/Berlin) | 11,090,829 | 185304 | 833161 | 0 |
| 2026-09-13 16:57 CEST (Europe/Berlin) | 11,095,437 | 185292 | 833086 | 0 |
| 2026-09-13 18:45 CEST (Europe/Berlin) | 11,098,270 | 185279 | 833054 | 0 |
| 2026-09-13 23:12 CEST (Europe/Berlin) | 11,103,715 | 185251 | 832993 | 0 |
| 2026-09-13 23:15 CEST (Europe/Berlin) | 11,103,715 | 185251 | 832993 | 0 |
| 2026-09-14 01:28 CEST (Europe/Berlin) | 11,106,292 | 185243 | 832986 | 0 |
| 2026-09-14 01:49 CEST (Europe/Berlin) | 11,106,292 | 185243 | 832986 | 0 |
