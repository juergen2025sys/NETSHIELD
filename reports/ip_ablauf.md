# Seen-DB Expiry Forecast

Lauf: 2026-09-14 09:50 CEST (Europe/Berlin)
Gesamt: 11,125,038 IPs in seen_db.json (8,219,017 aktiv/180-Tage-Pfad, 2,906,021 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 101,590 |
| 15-30 Tage | 2,156,539 |
| 31-60 Tage | 890,458 |
| 61-90 Tage | 1,074,061 |
| 91-180 Tage | 3,996,369 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 522,290 |
| 0-3 Tage | 40,447 |
| 4-7 Tage | 24,040 |
| 8-14 Tage | 664,589 |
| 15-30 Tage | 1,654,655 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-14 | 12,843 |
| 2026-09-15 | 15,589 |
| 2026-09-16 | 6,244 |
| 2026-09-17 | 5,771 |
| 2026-09-18 | 8,793 |
| 2026-09-19 | 5,150 |
| 2026-09-20 | 5,058 |
| 2026-09-21 | 5,039 |
| 2026-09-22 | 11,186 |
| 2026-09-23 | 5,147 |
| 2026-09-24 | 11,430 |
| 2026-09-25 | 5,499 |
| 2026-09-26 | 624,217 |
| 2026-09-27 | 6,328 |
| 2026-09-28 | 782 |
| 2026-09-30 | 59,855 |
| 2026-10-01 | 7,709 |
| 2026-10-02 | 1,309,006 |
| 2026-10-03 | 2,991 |
| 2026-10-04 | 6,973 |
| 2026-10-05 | 2,928 |
| 2026-10-06 | 8,332 |
| 2026-10-07 | 8,072 |
| 2026-10-08 | 7,376 |
| 2026-10-09 | 152,412 |
| 2026-10-10 | 8,287 |
| 2026-10-11 | 23,363 |
| 2026-10-12 | 33,461 |
| 2026-10-13 | 9,206 |
| 2026-10-14 | 8,408 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **522,290** IPs. Brutto faellig in den naechsten 30 Tagen: **2,377,455**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,839,745**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-14 | 12,843 | 2,000 |
| 2026-09-15 | 15,589 | 2,000 |
| 2026-09-16 | 6,244 | 2,000 |
| 2026-09-17 | 5,771 | 2,000 |
| 2026-09-18 | 8,793 | 2,000 |
| 2026-09-19 | 5,150 | 2,000 |
| 2026-09-20 | 5,058 | 2,000 |
| 2026-09-21 | 5,039 | 2,000 |
| 2026-09-22 | 11,186 | 2,000 |
| 2026-09-23 | 5,147 | 2,000 |
| 2026-09-24 | 11,430 | 2,000 |
| 2026-09-25 | 5,499 | 2,000 |
| 2026-09-26 | 624,217 | 2,000 |
| 2026-09-27 | 6,328 | 2,000 |
| 2026-09-28 | 782 | 2,000 |
| 2026-09-30 | 59,855 | 2,000 |
| 2026-10-01 | 7,709 | 2,000 |
| 2026-10-02 | 1,309,006 | 2,000 |
| 2026-10-03 | 2,991 | 2,000 |
| 2026-10-04 | 6,973 | 2,000 |
| 2026-10-05 | 2,928 | 2,000 |
| 2026-10-06 | 8,332 | 2,000 |
| 2026-10-07 | 8,072 | 2,000 |
| 2026-10-08 | 7,376 | 2,000 |
| 2026-10-09 | 152,412 | 2,000 |
| 2026-10-10 | 8,287 | 2,000 |
| 2026-10-11 | 23,363 | 2,000 |
| 2026-10-12 | 33,461 | 2,000 |
| 2026-10-13 | 9,206 | 2,000 |
| 2026-10-14 | 8,408 | 2,000 |

> Hinweis: Der Rueckstau von 2,839,745 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,448 |
| 2026-09-23 | 13,102 |
| 2026-09-24 | 16,744 |
| 2026-09-25 | 21,016 |
| 2026-09-26 | 17,522 |
| 2026-09-27 | 15,124 |
| 2026-09-28 | 11,634 |
| 2026-09-29 | 9,392 |
| 2026-09-30 | 10,239 |
| 2026-10-01 | 16,655 |
| 2026-10-02 | 7,757 |
| 2026-10-03 | 7,370 |
| 2026-10-04 | 12,700 |
| 2026-10-05 | 17,625 |
| 2026-10-06 | 16,198 |
| 2026-10-07 | 15,130 |
| 2026-10-08 | 61,761 |
| 2026-10-09 | 224,375 |
| 2026-10-10 | 53,461 |
| 2026-10-11 | 16,083 |
| 2026-10-12 | 66,646 |
| 2026-10-13 | 1,588,204 |
| 2026-10-14 | 32,943 |
| 2026-10-15 | 41,417 |
| 2026-10-16 | 51,444 |
| 2026-10-17 | 24,412 |
| 2026-10-18 | 14,338 |
| 2026-10-19 | 22,542 |
| 2026-10-20 | 11,188 |
| 2026-10-21 | 11,163 |
| 2026-10-22 | 30,871 |
| 2026-10-23 | 50,545 |
| 2026-10-24 | 41,847 |
| 2026-10-25 | 21,710 |
| 2026-10-26 | 20,458 |
| 2026-10-27 | 20,812 |
| 2026-10-28 | 15,876 |
| 2026-10-29 | 9,763 |
| 2026-10-30 | 62,222 |
| 2026-10-31 | 88,351 |
| 2026-11-01 | 27,997 |
| 2026-11-02 | 28,983 |
| 2026-11-03 | 30,025 |
| 2026-11-04 | 29,817 |
| 2026-11-05 | 25,421 |
| 2026-11-06 | 36,856 |
| 2026-11-07 | 24,608 |
| 2026-11-08 | 26,274 |
| 2026-11-09 | 25,717 |
| 2026-11-10 | 32,918 |
| 2026-11-11 | 22,520 |
| 2026-11-12 | 20,603 |
| 2026-11-13 | 19,760 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191222 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
