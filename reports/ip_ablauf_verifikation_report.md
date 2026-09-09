# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-10 01:42 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 186477 |
| Active (180-Tage-Pfad) | 834962 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt jetzt die TATSAECHLICH an diesem Kalendertag vom Combined-Lauf entfernten IPs (`expired_watchlist` bzw. `expired_active`). Damit werden Watchlist-Rueckstaende durch den 2.000/Tag-Deckel korrekt dem realen Entfernungstag zugerechnet. Dieselbe Ist-Logik gilt fuer Active/180T, damit auch verspaetete Cleanup-Laeufe nicht dem theoretischen Faelligkeitsdatum zugeschrieben werden.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-10 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-11 | 2,000 | 0 | 0% |
| 2026-09-12 | 2,000 | 0 | 0% |
| 2026-09-13 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 6,469 | 0 | 0% |
| 2026-09-23 | 13,144 | 0 | 0% |
| 2026-09-24 | 16,812 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **143,258 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **514 Treffer sind legitime Watchlist→Active-Aufstiege und kein Anti-Churn-Rückfall.** Diese IPs stehen im Watchlist-Ledger, wurden aber per echter Zweitbestätigung (2+ HQ-Familien) direkt in den Active-Pfad aufgenommen und stehen deshalb in `active_blacklist_ipv4.txt`, ohne (noch) im Active-Ledger zu stehen. Spiegelbild des Active→Watchlist-Falls oben.

ℹ️ **174,555 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 477,945 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-10). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 143,258 legitime Active→Watchlist-Treffer; 514 legitime Watchlist→Active-Treffer; 174,555 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

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

_30 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |

_49 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +732 (Anstieg) (jetzt 10,837,423 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,441,384 (Anstieg)
- Letzter combined-Cleanup-Pass: 294,228 IPs durch Ablauf entfernt (davon 2,000 Watchlist/30T, 292,228 Active/180T), 1,125,841 neue IPs hinzugekommen (davon 939,182 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 37 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 188,064 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,939,645 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 2,341,136 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 2,339,136 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +26,383 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-09T09:43 bis 2026-09-09T23:30 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
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
| 2026-09-09 07:37 CEST (Europe/Berlin) | 10,811,040 | 186478 | 835311 | 0 |
| 2026-09-09 14:04 CEST (Europe/Berlin) | 10,822,006 | 186477 | 835255 | 0 |
| 2026-09-09 18:56 CEST (Europe/Berlin) | 10,829,715 | 186477 | 835128 | 0 |
| 2026-09-09 18:57 CEST (Europe/Berlin) | 10,829,715 | 186477 | 835128 | 0 |
| 2026-09-09 21:43 CEST (Europe/Berlin) | 10,835,343 | 186477 | 835059 | 0 |
| 2026-09-09 23:25 CEST (Europe/Berlin) | 10,836,691 | 186477 | 835044 | 0 |
| 2026-09-10 00:30 CEST (Europe/Berlin) | 10,836,691 | 186477 | 835044 | 0 |
| 2026-09-10 01:42 CEST (Europe/Berlin) | 10,837,423 | 186477 | 834962 | 0 |
