# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-09 01:47 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 186478 |
| Active (180-Tage-Pfad) | 835439 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt jetzt die TATSAECHLICH an diesem Kalendertag vom Combined-Lauf entfernten IPs (`expired_watchlist` bzw. `expired_active`). Damit werden Watchlist-Rueckstaende durch den 2.000/Tag-Deckel korrekt dem realen Entfernungstag zugerechnet. Dieselbe Ist-Logik gilt fuer Active/180T, damit auch verspaetete Cleanup-Laeufe nicht dem theoretischen Faelligkeitsdatum zugeschrieben werden.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-09 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-10 | 2,000 | 0 | 0% |
| 2026-09-11 | 2,000 | 0 | 0% |
| 2026-09-12 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 6,471 | 0 | 0% |
| 2026-09-23 | 13,153 | 0 | 0% |
| 2026-09-24 | 16,827 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **142,662 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **437 Treffer sind legitime Watchlist→Active-Aufstiege und kein Anti-Churn-Rückfall.** Diese IPs stehen im Watchlist-Ledger, wurden aber per echter Zweitbestätigung (2+ HQ-Familien) direkt in den Active-Pfad aufgenommen und stehen deshalb in `active_blacklist_ipv4.txt`, ohne (noch) im Active-Ledger zu stehen. Spiegelbild des Active→Watchlist-Falls oben.

ℹ️ **176,570 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 461,624 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-09). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 142,662 legitime Active→Watchlist-Treffer; 437 legitime Watchlist→Active-Treffer; 176,570 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

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
| 2026-09-07 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-08 | 2,000 | 0 | 2,000 | 100.0% |

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |

_48 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +238 (Anstieg) (jetzt 10,785,750 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,389,711 (Anstieg)
- Letzter combined-Cleanup-Pass: 294,249 IPs durch Ablauf entfernt (davon 2,000 Watchlist/30T, 292,249 Active/180T), 1,131,853 neue IPs hinzugekommen (davon 942,079 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 172 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 191,725 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 9,070,531 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 2,340,826 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 2,338,826 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +39,202 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-08T11:44 bis 2026-09-08T23:39 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-06 22:58 CEST (Europe/Berlin) | 11,155,666 | 186481 | 173624 | 300 |
| 2026-09-07 01:22 CEST (Europe/Berlin) | 11,158,149 | 186481 | 173624 | 301 |
| 2026-09-07 01:47 CEST (Europe/Berlin) | 11,158,149 | 186481 | 173624 | 301 |
| 2026-09-07 06:19 CEST (Europe/Berlin) | 11,163,016 | 186481 | 173619 | 308 |
| 2026-09-07 07:30 CEST (Europe/Berlin) | 11,170,094 | 186480 | 173619 | 311 |
| 2026-09-07 11:42 CEST (Europe/Berlin) | 11,171,671 | 186480 | 173619 | 316 |
| 2026-09-07 15:11 CEST (Europe/Berlin) | 11,190,798 | 186480 | 173619 | 334 |
| 2026-09-07 17:07 CEST (Europe/Berlin) | 11,190,798 | 186480 | 173619 | 0 |
| 2026-09-07 21:30 CEST (Europe/Berlin) | 11,214,280 | 186480 | 173616 | 0 |
| 2026-09-08 00:49 CEST (Europe/Berlin) | 11,230,473 | 186480 | 173611 | 0 |
| 2026-09-08 01:53 CEST (Europe/Berlin) | 11,230,473 | 186480 | 173611 | 0 |
| 2026-09-08 07:30 CEST (Europe/Berlin) | 10,720,545 | 186480 | 835881 | 0 |
| 2026-09-08 13:45 CEST (Europe/Berlin) | 10,746,548 | 186479 | 835751 | 0 |
| 2026-09-08 13:55 CEST (Europe/Berlin) | 10,746,548 | 186479 | 835751 | 0 |
| 2026-09-08 18:34 CEST (Europe/Berlin) | 10,762,899 | 186478 | 835620 | 0 |
| 2026-09-08 18:57 CEST (Europe/Berlin) | 10,762,899 | 186478 | 835620 | 0 |
| 2026-09-08 21:37 CEST (Europe/Berlin) | 10,777,942 | 186478 | 835513 | 0 |
| 2026-09-08 23:32 CEST (Europe/Berlin) | 10,785,512 | 186478 | 835460 | 0 |
| 2026-09-09 00:35 CEST (Europe/Berlin) | 10,785,512 | 186478 | 835460 | 0 |
| 2026-09-09 01:47 CEST (Europe/Berlin) | 10,785,750 | 186478 | 835439 | 0 |
