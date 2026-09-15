# Seen-DB Expiry Forecast

Lauf: 2026-09-15 03:50 CEST (Europe/Berlin)
Gesamt: 11,190,546 IPs in seen_db.json (8,282,316 aktiv/180-Tage-Pfad, 2,908,230 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 6,445 |
| 8-14 Tage | 104,482 |
| 15-30 Tage | 2,187,948 |
| 31-60 Tage | 871,873 |
| 61-90 Tage | 1,074,283 |
| 91-180 Tage | 4,037,285 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 534,891 |
| 0-3 Tage | 36,371 |
| 4-7 Tage | 26,415 |
| 8-14 Tage | 653,343 |
| 15-30 Tage | 1,657,210 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-15 | 15,576 |
| 2026-09-16 | 6,243 |
| 2026-09-17 | 5,766 |
| 2026-09-18 | 8,786 |
| 2026-09-19 | 5,144 |
| 2026-09-20 | 5,058 |
| 2026-09-21 | 5,035 |
| 2026-09-22 | 11,178 |
| 2026-09-23 | 5,139 |
| 2026-09-24 | 11,424 |
| 2026-09-25 | 5,495 |
| 2026-09-26 | 624,179 |
| 2026-09-27 | 6,325 |
| 2026-09-28 | 781 |
| 2026-09-30 | 59,831 |
| 2026-10-01 | 7,697 |
| 2026-10-02 | 1,308,830 |
| 2026-10-03 | 2,986 |
| 2026-10-04 | 6,960 |
| 2026-10-05 | 2,924 |
| 2026-10-06 | 8,319 |
| 2026-10-07 | 8,058 |
| 2026-10-08 | 7,369 |
| 2026-10-09 | 152,363 |
| 2026-10-10 | 8,273 |
| 2026-10-11 | 23,336 |
| 2026-10-12 | 33,438 |
| 2026-10-13 | 9,156 |
| 2026-10-14 | 8,216 |
| 2026-10-15 | 9,454 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **534,891** IPs. Brutto faellig in den naechsten 30 Tagen: **2,373,339**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,848,230**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-15 | 15,576 | 2,000 |
| 2026-09-16 | 6,243 | 2,000 |
| 2026-09-17 | 5,766 | 2,000 |
| 2026-09-18 | 8,786 | 2,000 |
| 2026-09-19 | 5,144 | 2,000 |
| 2026-09-20 | 5,058 | 2,000 |
| 2026-09-21 | 5,035 | 2,000 |
| 2026-09-22 | 11,178 | 2,000 |
| 2026-09-23 | 5,139 | 2,000 |
| 2026-09-24 | 11,424 | 2,000 |
| 2026-09-25 | 5,495 | 2,000 |
| 2026-09-26 | 624,179 | 2,000 |
| 2026-09-27 | 6,325 | 2,000 |
| 2026-09-28 | 781 | 2,000 |
| 2026-09-30 | 59,831 | 2,000 |
| 2026-10-01 | 7,697 | 2,000 |
| 2026-10-02 | 1,308,830 | 2,000 |
| 2026-10-03 | 2,986 | 2,000 |
| 2026-10-04 | 6,960 | 2,000 |
| 2026-10-05 | 2,924 | 2,000 |
| 2026-10-06 | 8,319 | 2,000 |
| 2026-10-07 | 8,058 | 2,000 |
| 2026-10-08 | 7,369 | 2,000 |
| 2026-10-09 | 152,363 | 2,000 |
| 2026-10-10 | 8,273 | 2,000 |
| 2026-10-11 | 23,336 | 2,000 |
| 2026-10-12 | 33,438 | 2,000 |
| 2026-10-13 | 9,156 | 2,000 |
| 2026-10-14 | 8,216 | 2,000 |
| 2026-10-15 | 9,454 | 2,000 |

> Hinweis: Der Rueckstau von 2,848,230 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,445 |
| 2026-09-23 | 13,097 |
| 2026-09-24 | 16,738 |
| 2026-09-25 | 21,006 |
| 2026-09-26 | 17,514 |
| 2026-09-27 | 15,106 |
| 2026-09-28 | 11,630 |
| 2026-09-29 | 9,391 |
| 2026-09-30 | 10,236 |
| 2026-10-01 | 16,652 |
| 2026-10-02 | 7,755 |
| 2026-10-03 | 7,364 |
| 2026-10-04 | 12,698 |
| 2026-10-05 | 17,619 |
| 2026-10-06 | 16,187 |
| 2026-10-07 | 15,120 |
| 2026-10-08 | 61,730 |
| 2026-10-09 | 224,247 |
| 2026-10-10 | 53,453 |
| 2026-10-11 | 16,082 |
| 2026-10-12 | 66,639 |
| 2026-10-13 | 1,587,811 |
| 2026-10-14 | 32,940 |
| 2026-10-15 | 41,415 |
| 2026-10-16 | 51,438 |
| 2026-10-17 | 24,401 |
| 2026-10-18 | 14,335 |
| 2026-10-19 | 22,530 |
| 2026-10-20 | 11,183 |
| 2026-10-21 | 11,161 |
| 2026-10-22 | 30,863 |
| 2026-10-23 | 50,537 |
| 2026-10-24 | 41,841 |
| 2026-10-25 | 21,703 |
| 2026-10-26 | 20,448 |
| 2026-10-27 | 20,802 |
| 2026-10-28 | 15,872 |
| 2026-10-29 | 9,762 |
| 2026-10-30 | 62,196 |
| 2026-10-31 | 88,341 |
| 2026-11-01 | 27,986 |
| 2026-11-02 | 28,972 |
| 2026-11-03 | 30,009 |
| 2026-11-04 | 29,802 |
| 2026-11-05 | 25,410 |
| 2026-11-06 | 36,844 |
| 2026-11-07 | 24,597 |
| 2026-11-08 | 26,268 |
| 2026-11-09 | 25,708 |
| 2026-11-10 | 32,905 |
| 2026-11-11 | 22,507 |
| 2026-11-12 | 20,597 |
| 2026-11-13 | 19,753 |
| 2026-11-14 | 23,102 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 191210 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
