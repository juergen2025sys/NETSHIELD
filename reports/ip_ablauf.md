# Seen-DB Expiry Forecast

Lauf: 2026-09-09 00:32 CEST (Europe/Berlin)
Gesamt: 10,785,512 IPs in seen_db.json (7,962,071 aktiv/180-Tage-Pfad, 2,823,441 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 0 |
| 8-14 Tage | 6,471 |
| 15-30 Tage | 271,083 |
| 31-60 Tage | 2,730,086 |
| 61-90 Tage | 1,026,103 |
| 91-180 Tage | 3,928,328 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 450,597 |
| 0-3 Tage | 50,145 |
| 4-7 Tage | 52,607 |
| 8-14 Tage | 47,503 |
| 15-30 Tage | 2,222,589 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-08 | 13,057 |
| 2026-09-09 | 16,966 |
| 2026-09-10 | 8,770 |
| 2026-09-11 | 11,352 |
| 2026-09-12 | 11,943 |
| 2026-09-13 | 12,091 |
| 2026-09-14 | 12,906 |
| 2026-09-15 | 15,667 |
| 2026-09-16 | 6,270 |
| 2026-09-17 | 5,813 |
| 2026-09-18 | 8,838 |
| 2026-09-19 | 5,176 |
| 2026-09-20 | 5,092 |
| 2026-09-21 | 5,074 |
| 2026-09-22 | 11,240 |
| 2026-09-23 | 5,188 |
| 2026-09-24 | 11,462 |
| 2026-09-25 | 5,531 |
| 2026-09-26 | 624,560 |
| 2026-09-27 | 6,373 |
| 2026-09-28 | 786 |
| 2026-09-30 | 60,024 |
| 2026-10-01 | 7,753 |
| 2026-10-02 | 1,310,331 |
| 2026-10-03 | 3,014 |
| 2026-10-04 | 7,016 |
| 2026-10-05 | 2,975 |
| 2026-10-06 | 8,483 |
| 2026-10-07 | 8,192 |
| 2026-10-08 | 7,505 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **450,597** IPs. Brutto faellig in den naechsten 30 Tagen: **2,219,448**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,610,045**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-08 | 13,057 | 2,000 |
| 2026-09-09 | 16,966 | 2,000 |
| 2026-09-10 | 8,770 | 2,000 |
| 2026-09-11 | 11,352 | 2,000 |
| 2026-09-12 | 11,943 | 2,000 |
| 2026-09-13 | 12,091 | 2,000 |
| 2026-09-14 | 12,906 | 2,000 |
| 2026-09-15 | 15,667 | 2,000 |
| 2026-09-16 | 6,270 | 2,000 |
| 2026-09-17 | 5,813 | 2,000 |
| 2026-09-18 | 8,838 | 2,000 |
| 2026-09-19 | 5,176 | 2,000 |
| 2026-09-20 | 5,092 | 2,000 |
| 2026-09-21 | 5,074 | 2,000 |
| 2026-09-22 | 11,240 | 2,000 |
| 2026-09-23 | 5,188 | 2,000 |
| 2026-09-24 | 11,462 | 2,000 |
| 2026-09-25 | 5,531 | 2,000 |
| 2026-09-26 | 624,560 | 2,000 |
| 2026-09-27 | 6,373 | 2,000 |
| 2026-09-28 | 786 | 2,000 |
| 2026-09-30 | 60,024 | 2,000 |
| 2026-10-01 | 7,753 | 2,000 |
| 2026-10-02 | 1,310,331 | 2,000 |
| 2026-10-03 | 3,014 | 2,000 |
| 2026-10-04 | 7,016 | 2,000 |
| 2026-10-05 | 2,975 | 2,000 |
| 2026-10-06 | 8,483 | 2,000 |
| 2026-10-07 | 8,192 | 2,000 |
| 2026-10-08 | 7,505 | 2,000 |

> Hinweis: Der Rueckstau von 2,610,045 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-22 | 6,471 |
| 2026-09-23 | 13,153 |
| 2026-09-24 | 16,827 |
| 2026-09-25 | 21,106 |
| 2026-09-26 | 17,604 |
| 2026-09-27 | 15,204 |
| 2026-09-28 | 11,669 |
| 2026-09-29 | 9,424 |
| 2026-09-30 | 10,282 |
| 2026-10-01 | 16,706 |
| 2026-10-02 | 7,797 |
| 2026-10-03 | 7,392 |
| 2026-10-04 | 12,772 |
| 2026-10-05 | 17,684 |
| 2026-10-06 | 16,253 |
| 2026-10-07 | 15,176 |
| 2026-10-08 | 62,034 |
| 2026-10-09 | 225,798 |
| 2026-10-10 | 53,517 |
| 2026-10-11 | 16,108 |
| 2026-10-12 | 66,695 |
| 2026-10-13 | 1,590,621 |
| 2026-10-14 | 32,961 |
| 2026-10-15 | 41,445 |
| 2026-10-16 | 51,501 |
| 2026-10-17 | 24,464 |
| 2026-10-18 | 14,380 |
| 2026-10-19 | 22,667 |
| 2026-10-20 | 11,216 |
| 2026-10-21 | 11,196 |
| 2026-10-22 | 30,966 |
| 2026-10-23 | 50,604 |
| 2026-10-24 | 41,914 |
| 2026-10-25 | 21,763 |
| 2026-10-26 | 20,522 |
| 2026-10-27 | 20,880 |
| 2026-10-28 | 15,937 |
| 2026-10-29 | 9,809 |
| 2026-10-30 | 62,393 |
| 2026-10-31 | 88,443 |
| 2026-11-01 | 28,057 |
| 2026-11-02 | 29,062 |
| 2026-11-03 | 30,137 |
| 2026-11-04 | 29,923 |
| 2026-11-05 | 25,494 |
| 2026-11-06 | 36,946 |
| 2026-11-07 | 24,667 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 142642 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
