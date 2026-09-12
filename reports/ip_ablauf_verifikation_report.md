# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-12 03:31 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 186473 |
| Active (180-Tage-Pfad) | 833779 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt jetzt die TATSAECHLICH an diesem Kalendertag vom Combined-Lauf entfernten IPs (`expired_watchlist` bzw. `expired_active`). Damit werden Watchlist-Rueckstaende durch den 2.000/Tag-Deckel korrekt dem realen Entfernungstag zugerechnet. Dieselbe Ist-Logik gilt fuer Active/180T, damit auch verspaetete Cleanup-Laeufe nicht dem theoretischen Faelligkeitsdatum zugeschrieben werden.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-12 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-13 | 2,000 | 0 | 0% |
| 2026-09-14 | 2,000 | 0 | 0% |
| 2026-09-15 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 6,458 | 0 | 0% |
| 2026-09-23 | 13,117 | 0 | 0% |
| 2026-09-24 | 16,773 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **189,754 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **619 Treffer sind legitime Watchlist→Active-Aufstiege und kein Anti-Churn-Rückfall.** Diese IPs stehen im Watchlist-Ledger, wurden aber per echter Zweitbestätigung (2+ HQ-Familien) direkt in den Active-Pfad aufgenommen und stehen deshalb in `active_blacklist_ipv4.txt`, ohne (noch) im Active-Ledger zu stehen. Spiegelbild des Active→Watchlist-Falls oben.

ℹ️ **176,502 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 509,586 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-12). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 189,754 legitime Active→Watchlist-Treffer; 619 legitime Watchlist→Active-Treffer; 176,502 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

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
| 2026-09-09 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-10 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-11 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |

_52 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +745 (Anstieg) (jetzt 11,010,142 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,614,103 (Anstieg)
- Letzter combined-Cleanup-Pass: 247,470 IPs durch Ablauf entfernt (davon 2,000 Watchlist/30T, 245,470 Active/180T), 1,073,770 neue IPs hinzugekommen (davon 939,449 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 37 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 1 geschützt entfernt, 135,699 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,598,271 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,966,090 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 1,964,090 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +17,533 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-11T11:49 bis 2026-09-12T00:30 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-10 00:30 CEST (Europe/Berlin) | 10,836,691 | 186477 | 835044 | 0 |
| 2026-09-10 01:42 CEST (Europe/Berlin) | 10,837,423 | 186477 | 834962 | 0 |
| 2026-09-10 07:28 CEST (Europe/Berlin) | 10,850,123 | 186476 | 834870 | 0 |
| 2026-09-10 13:10 CEST (Europe/Berlin) | 10,860,609 | 186476 | 834705 | 0 |
| 2026-09-10 13:59 CEST (Europe/Berlin) | 10,860,609 | 186476 | 834705 | 0 |
| 2026-09-10 17:10 CEST (Europe/Berlin) | 10,867,293 | 186476 | 834652 | 0 |
| 2026-09-10 18:48 CEST (Europe/Berlin) | 10,879,779 | 186476 | 834518 | 0 |
| 2026-09-10 23:20 CEST (Europe/Berlin) | 10,886,561 | 186476 | 834418 | 0 |
| 2026-09-11 01:35 CEST (Europe/Berlin) | 10,906,266 | 186476 | 834351 | 0 |
| 2026-09-11 06:29 CEST (Europe/Berlin) | 10,925,392 | 186475 | 834234 | 0 |
| 2026-09-11 07:29 CEST (Europe/Berlin) | 10,935,002 | 186475 | 834218 | 0 |
| 2026-09-11 11:09 CEST (Europe/Berlin) | 10,975,165 | 186475 | 834196 | 0 |
| 2026-09-11 13:58 CEST (Europe/Berlin) | 10,992,609 | 186475 | 834019 | 0 |
| 2026-09-11 15:49 CEST (Europe/Berlin) | 10,992,609 | 186475 | 834019 | 0 |
| 2026-09-11 18:50 CEST (Europe/Berlin) | 11,002,546 | 186475 | 833917 | 0 |
| 2026-09-11 22:55 CEST (Europe/Berlin) | 11,007,871 | 186474 | 833844 | 0 |
| 2026-09-11 23:28 CEST (Europe/Berlin) | 11,007,871 | 186474 | 833844 | 0 |
| 2026-09-12 01:13 CEST (Europe/Berlin) | 11,009,397 | 186474 | 833826 | 0 |
| 2026-09-12 01:44 CEST (Europe/Berlin) | 11,009,397 | 186474 | 833826 | 0 |
| 2026-09-12 03:31 CEST (Europe/Berlin) | 11,010,142 | 186473 | 833779 | 0 |
