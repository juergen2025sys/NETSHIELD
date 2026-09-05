# Seen-DB Expiry Forecast

Lauf: 2026-09-05 14:33 CEST (Europe/Berlin)
Gesamt: 11,039,912 IPs in seen_db.json (8,384,780 aktiv/180-Tage-Pfad, 2,655,132 Watchlist/30-Tage-Pfad)

## Aktive IPs (180-Tage-Fenster) – wann faellt die Bestaetigung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig (Cleanup-Pass sollte das entfernen) | 0 |
| 0-7 Tage | 662,933 |
| 8-14 Tage | 0 |
| 15-30 Tage | 184,528 |
| 31-60 Tage | 2,739,799 |
| 61-90 Tage | 1,034,027 |
| 91-180 Tage | 3,763,493 |

## Watchlist-IPs (30-Tage-Fenster) – wann faellt die Erstsichtung aus?

| Zeitfenster | Anzahl IPs |
|---|---:|
| bereits ueberfaellig | 344,777 |
| 0-3 Tage | 119,164 |
| 4-7 Tage | 49,209 |
| 8-14 Tage | 66,994 |
| 15-30 Tage | 2,074,988 |

## Konkrete Ablauftermine, Watchlist-IPs, naechste 30 Tage

Tagesgenau, im Gegensatz zu den groben Zeitfenstern oben - damit sich der Anti-Churn-Fix (eingefrorene first-Daten bei erneutem Auftauchen, siehe state/watchlist_expired_history.json) konkret nachvollziehen laesst: Faellt die IP-Zahl an einem vorhergesagten Tag tatsaechlich, und bleibt sie danach unten (pruefbar zusaetzlich mit dem Job "verifikation" in dieser Datei, der aktiv auf Rueckkehrer prueft)?

| Datum | Anzahl IPs, die an diesem Tag ihre Erstsichtungs-Frist verlieren |
|---|---:|
| 2026-09-05 | 69,304 |
| 2026-09-06 | 20,506 |
| 2026-09-07 | 16,264 |
| 2026-09-08 | 13,090 |
| 2026-09-09 | 17,025 |
| 2026-09-10 | 8,815 |
| 2026-09-11 | 11,392 |
| 2026-09-12 | 11,977 |
| 2026-09-13 | 12,116 |
| 2026-09-14 | 12,954 |
| 2026-09-15 | 15,719 |
| 2026-09-16 | 6,296 |
| 2026-09-17 | 5,842 |
| 2026-09-18 | 8,873 |
| 2026-09-19 | 5,194 |
| 2026-09-20 | 5,108 |
| 2026-09-21 | 5,098 |
| 2026-09-22 | 11,278 |
| 2026-09-23 | 5,202 |
| 2026-09-24 | 11,486 |
| 2026-09-25 | 5,568 |
| 2026-09-26 | 624,746 |
| 2026-09-27 | 6,410 |
| 2026-09-28 | 790 |
| 2026-09-30 | 60,134 |
| 2026-10-01 | 7,785 |
| 2026-10-02 | 1,311,201 |
| 2026-10-03 | 3,039 |
| 2026-10-04 | 7,070 |
| 2026-10-05 | 3,520 |

## Erwartete tatsaechliche Watchlist-Entfernungen (mit Tagesdeckel)

update_combined_blacklist.yml entfernt ueber die 30-Tage-Regel hoechstens **2,000 IPs pro Kalendertag** (FIX WATCHLIST-DAILY-CAP, 31.08.2026). Ueberzaehlige Kandidaten bleiben in seen_db und ruecken nach hinten - es geht nichts verloren, der Abbau wird nur gestreckt. Die rechte Spalte ist deshalb die realistische Erwartung, gegen die der Job "verifikation" prueft.

Bereits ueberfaelliger Rueckstau zu Beginn: **344,777** IPs. Brutto faellig in den naechsten 30 Tagen: **2,303,802**, davon im selben Fenster tatsaechlich entfernbar: **60,000**. Verbleibender Rueckstau am Fensterende: **2,588,579**.

| Datum | Brutto faellig | Erwartet entfernt (mit Deckel) |
|---|---:|---:|
| 2026-09-05 | 69,304 | 2,000 |
| 2026-09-06 | 20,506 | 2,000 |
| 2026-09-07 | 16,264 | 2,000 |
| 2026-09-08 | 13,090 | 2,000 |
| 2026-09-09 | 17,025 | 2,000 |
| 2026-09-10 | 8,815 | 2,000 |
| 2026-09-11 | 11,392 | 2,000 |
| 2026-09-12 | 11,977 | 2,000 |
| 2026-09-13 | 12,116 | 2,000 |
| 2026-09-14 | 12,954 | 2,000 |
| 2026-09-15 | 15,719 | 2,000 |
| 2026-09-16 | 6,296 | 2,000 |
| 2026-09-17 | 5,842 | 2,000 |
| 2026-09-18 | 8,873 | 2,000 |
| 2026-09-19 | 5,194 | 2,000 |
| 2026-09-20 | 5,108 | 2,000 |
| 2026-09-21 | 5,098 | 2,000 |
| 2026-09-22 | 11,278 | 2,000 |
| 2026-09-23 | 5,202 | 2,000 |
| 2026-09-24 | 11,486 | 2,000 |
| 2026-09-25 | 5,568 | 2,000 |
| 2026-09-26 | 624,746 | 2,000 |
| 2026-09-27 | 6,410 | 2,000 |
| 2026-09-28 | 790 | 2,000 |
| 2026-09-30 | 60,134 | 2,000 |
| 2026-10-01 | 7,785 | 2,000 |
| 2026-10-02 | 1,311,201 | 2,000 |
| 2026-10-03 | 3,039 | 2,000 |
| 2026-10-04 | 7,070 | 2,000 |
| 2026-10-05 | 3,520 | 2,000 |

> Hinweis: Der Rueckstau von 2,588,579 IPs waechst schneller, als der Tagesdeckel ihn abbauen kann. Bei dauerhaftem Trend WATCHLIST_DAILY_CAP in update_combined_blacklist.yml anheben.

## Konkrete Ablauftermine, aktive IPs, naechste 60 Tage

Zeigt einzelne Tage mit ueberdurchschnittlich vielen gleichzeitig ablaufenden IPs (z.B. durch einen einmaligen Massenimport an einem bestimmten Tag vor 180 Tagen).

| Datum | Anzahl IPs, die an diesem Tag ihre Bestaetigung verlieren |
|---|---:|
| 2026-09-08 | 662,933 |
| 2026-09-22 | 6,488 |
| 2026-09-23 | 13,189 |
| 2026-09-24 | 16,874 |
| 2026-09-25 | 21,155 |
| 2026-09-26 | 17,660 |
| 2026-09-27 | 15,242 |
| 2026-09-28 | 11,685 |
| 2026-09-29 | 9,448 |
| 2026-09-30 | 10,304 |
| 2026-10-01 | 16,740 |
| 2026-10-02 | 7,815 |
| 2026-10-03 | 7,409 |
| 2026-10-04 | 12,799 |
| 2026-10-05 | 17,720 |
| 2026-10-06 | 16,290 |
| 2026-10-07 | 15,210 |
| 2026-10-08 | 62,203 |
| 2026-10-09 | 226,431 |
| 2026-10-10 | 53,545 |
| 2026-10-11 | 16,122 |
| 2026-10-12 | 66,716 |
| 2026-10-13 | 1,592,087 |
| 2026-10-14 | 32,968 |
| 2026-10-15 | 41,461 |
| 2026-10-16 | 51,534 |
| 2026-10-17 | 24,504 |
| 2026-10-18 | 14,407 |
| 2026-10-19 | 22,749 |
| 2026-10-20 | 11,243 |
| 2026-10-21 | 11,225 |
| 2026-10-22 | 31,016 |
| 2026-10-23 | 50,649 |
| 2026-10-24 | 41,957 |
| 2026-10-25 | 21,813 |
| 2026-10-26 | 20,568 |
| 2026-10-27 | 20,918 |
| 2026-10-28 | 15,960 |
| 2026-10-29 | 9,834 |
| 2026-10-30 | 62,490 |
| 2026-10-31 | 88,502 |
| 2026-11-01 | 28,095 |
| 2026-11-02 | 29,115 |
| 2026-11-03 | 30,202 |
| 2026-11-04 | 29,985 |

## Ledger-Konsistenz (gegen aktuelle seen_db geprüft)

✅ Keine Inkonsistenzen - alle Ablauf-Listen-IPs, die noch/wieder in seen_db stehen, haben das erwartete eingefrorene Datum (oder eine plausible echte Neubestätigung).

*Hinweis: Beim Active-Pfad sind zwei Wiederaufnahmen legitim: schwache neue Evidenz darf die IP mit `last=Sentinel` auf den Watchlist-Pfad bringen; eine echte Zweitbestaetigung (2+ HQ-Feed-Familien) darf ein neueres `last` setzen und sie wieder Active machen. Beide Zustaende sind kein Freeze-Bypass.*

ℹ️ 221 Active-Ledger-IP(s) stehen aktuell legitim auf dem Watchlist-Pfad (schwache Neubestaetigung).
