# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-15 23:51 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 8301 |
| Active (180-Tage-Pfad) | 832266 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt jetzt die TATSAECHLICH an diesem Kalendertag vom Combined-Lauf entfernten IPs (`expired_watchlist` bzw. `expired_active`). Damit werden Watchlist-Rueckstaende durch den 2.000/Tag-Deckel korrekt dem realen Entfernungstag zugerechnet. Dieselbe Ist-Logik gilt fuer Active/180T, damit auch verspaetete Cleanup-Laeufe nicht dem theoretischen Faelligkeitsdatum zugeschrieben werden.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-15 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-16 | 2,000 | 0 | 0% |
| 2026-09-17 | 2,000 | 0 | 0% |
| 2026-09-18 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-21 | 6,509 | 0 | 0% |
| 2026-09-22 | 6,441 | 0 | 0% |
| 2026-09-23 | 13,089 | 0 | 0% |
| 2026-09-24 | 16,724 | 0 | 0% |

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **191,765 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **1 Treffer sind legitime Watchlist→Active-Aufstiege und kein Anti-Churn-Rückfall.** Diese IPs stehen im Watchlist-Ledger, wurden aber per echter Zweitbestätigung (2+ HQ-Familien) direkt in den Active-Pfad aufgenommen und stehen deshalb in `active_blacklist_ipv4.txt`, ohne (noch) im Active-Ledger zu stehen. Spiegelbild des Active→Watchlist-Falls oben.

ℹ️ **7,983 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 548,444 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-15). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 191,765 legitime Active→Watchlist-Treffer; 1 legitime Watchlist→Active-Treffer; 7,983 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-09-14 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |

_55 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +13,974 (Anstieg) (jetzt 11,292,784 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +1,896,745 (Anstieg)
- Letzter combined-Cleanup-Pass: 244,584 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 244,584 Active/180T), 1,043,946 neue IPs hinzugekommen (davon 935,775 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 278 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 4 Whitelist-Bereinigung, 94,483 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,608,344 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,960,555 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 1,958,555 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +102,238 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-15T04:43 bis 2026-09-15T21:46 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-13 23:12 CEST (Europe/Berlin) | 11,103,715 | 185251 | 832993 | 0 |
| 2026-09-13 23:15 CEST (Europe/Berlin) | 11,103,715 | 185251 | 832993 | 0 |
| 2026-09-14 01:28 CEST (Europe/Berlin) | 11,106,292 | 185243 | 832986 | 0 |
| 2026-09-14 01:49 CEST (Europe/Berlin) | 11,106,292 | 185243 | 832986 | 0 |
| 2026-09-14 03:34 CEST (Europe/Berlin) | 11,106,866 | 178008 | 832936 | 0 |
| 2026-09-14 07:35 CEST (Europe/Berlin) | 11,116,435 | 177996 | 832909 | 0 |
| 2026-09-14 09:53 CEST (Europe/Berlin) | 11,125,038 | 177989 | 832879 | 0 |
| 2026-09-14 15:32 CEST (Europe/Berlin) | 11,139,256 | 177969 | 832788 | 0 |
| 2026-09-14 21:52 CEST (Europe/Berlin) | 11,166,289 | 177934 | 832715 | 0 |
| 2026-09-14 22:05 CEST (Europe/Berlin) | 11,166,289 | 177934 | 832715 | 0 |
| 2026-09-15 01:07 CEST (Europe/Berlin) | 11,183,419 | 177899 | 832649 | 0 |
| 2026-09-15 02:06 CEST (Europe/Berlin) | 11,183,419 | 177899 | 832649 | 0 |
| 2026-09-15 03:53 CEST (Europe/Berlin) | 11,190,546 | 177885 | 832613 | 0 |
| 2026-09-15 07:37 CEST (Europe/Berlin) | 11,201,054 | 177863 | 832588 | 0 |
| 2026-09-15 09:39 CEST (Europe/Berlin) | 11,226,826 | 8309 | 832532 | 0 |
| 2026-09-15 14:23 CEST (Europe/Berlin) | 11,251,284 | 8307 | 832377 | 0 |
| 2026-09-15 15:29 CEST (Europe/Berlin) | 11,251,284 | 8307 | 832377 | 0 |
| 2026-09-15 19:25 CEST (Europe/Berlin) | 11,266,947 | 8302 | 832324 | 0 |
| 2026-09-15 23:13 CEST (Europe/Berlin) | 11,278,810 | 8301 | 832294 | 0 |
| 2026-09-15 23:51 CEST (Europe/Berlin) | 11,292,784 | 8301 | 832266 | 0 |
