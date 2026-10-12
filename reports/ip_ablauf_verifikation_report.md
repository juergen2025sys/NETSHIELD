# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-12 21:31 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 24526 |
| Active (180-Tage-Pfad) | 1454106 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-12 (heute) | 2,000 | 2,000 | 100% |
| 2026-10-13 | 2,000 | 0 | 0% |
| 2026-10-14 | 2,000 | 0 | 0% |
| 2026-10-15 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-12 (heute) | 66,480 | 66,477 | 0 | regulaerer Tagesstand |
| 2026-10-13 | 1,579,746 | 0 | – | noch nicht faellig |
| 2026-10-14 | 32,901 | 0 | – | noch nicht faellig |
| 2026-10-15 | 41,271 | 0 | – | noch nicht faellig |

**Active heute:** 66,477 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **2,306 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,653,063 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-12). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 2,306 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-28 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-29 | 60,458 | 0 | 60,458 | 100.0% |
| 2026-09-30 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-01 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-02 | 2,000 | 2,000 | 0 | 0.0% |
| 2026-10-03 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-04 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-05 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-06 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-07 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-08 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-09 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-10 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-11 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-28 | 11,588 | 11,587 | 1 | 0.0% |
| 2026-09-29 | 9,326 | 9,318 | 8 | 0.1% |
| 2026-09-30 | 10,132 | 10,126 | 6 | 0.1% |
| 2026-10-01 | 16,547 | 16,532 | 15 | 0.1% |
| 2026-10-02 | 7,694 | 7,681 | 13 | 0.2% |
| 2026-10-03 | 7,291 | 7,288 | 3 | 0.0% |
| 2026-10-04 | 12,537 | 12,528 | 9 | 0.1% |
| 2026-10-05 | 17,446 | 17,441 | 5 | 0.0% |
| 2026-10-06 | 16,020 | 16,001 | 19 | 0.1% |
| 2026-10-07 | 14,942 | 14,928 | 14 | 0.1% |
| 2026-10-08 | 60,917 | 60,866 | 51 | 0.1% |
| 2026-10-09 | 220,692 | 220,508 | 184 | 0.1% |
| 2026-10-10 | 53,244 | 53,239 | 5 | 0.0% |
| 2026-10-11 | 15,987 | 15,987 | 0 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +42,703 (Anstieg) (jetzt 12,303,301 IPs)
- Seit Zyklus-Start (2026-09-22): 📈 +825,582 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 906,982 neue IPs hinzugekommen (davon 767,535 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 35 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 120,963 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,183,248 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 136,958 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 4,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 132,958 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +7,790 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-11T18:30 bis 2026-10-12T19:10 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-10 00:59 CEST (Europe/Berlin) | 12,247,560 | 20028 | 1318869 | 0 |
| 2026-10-10 08:25 CEST (Europe/Berlin) | 12,210,251 | 21873 | 1372010 | 0 |
| 2026-10-10 08:34 CEST (Europe/Berlin) | 12,210,251 | 21873 | 1372010 | 0 |
| 2026-10-10 15:07 CEST (Europe/Berlin) | 12,251,421 | 21869 | 1371989 | 0 |
| 2026-10-10 15:10 CEST (Europe/Berlin) | 12,251,421 | 21869 | 1371989 | 0 |
| 2026-10-10 19:50 CEST (Europe/Berlin) | 12,260,874 | 21868 | 1371976 | 0 |
| 2026-10-10 21:39 CEST (Europe/Berlin) | 12,265,633 | 21868 | 1371967 | 0 |
| 2026-10-11 02:36 CEST (Europe/Berlin) | 12,271,665 | 22688 | 1387933 | 15987 |
| 2026-10-11 02:38 CEST (Europe/Berlin) | 12,261,224 | 22688 | 1387933 | 15987 |
| 2026-10-11 08:23 CEST (Europe/Berlin) | 12,273,613 | 22688 | 1387918 | 0 |
| 2026-10-11 08:41 CEST (Europe/Berlin) | 12,273,613 | 22688 | 1387918 | 0 |
| 2026-10-11 15:27 CEST (Europe/Berlin) | 12,295,511 | 22688 | 1387870 | 0 |
| 2026-10-11 15:40 CEST (Europe/Berlin) | 12,295,511 | 22688 | 1387870 | 0 |
| 2026-10-11 20:28 CEST (Europe/Berlin) | 12,301,285 | 22688 | 1387834 | 0 |
| 2026-10-11 21:49 CEST (Europe/Berlin) | 12,308,165 | 22688 | 1387824 | 0 |
| 2026-10-12 00:28 CEST (Europe/Berlin) | 12,314,398 | 22688 | 1387787 | 0 |
| 2026-10-12 02:52 CEST (Europe/Berlin) | 12,250,518 | 24526 | 1454238 | 0 |
| 2026-10-12 03:44 CEST (Europe/Berlin) | 12,250,518 | 24526 | 1454238 | 0 |
| 2026-10-12 08:58 CEST (Europe/Berlin) | 12,260,598 | 24526 | 1454202 | 0 |
| 2026-10-12 21:31 CEST (Europe/Berlin) | 12,303,301 | 24526 | 1454106 | 0 |
