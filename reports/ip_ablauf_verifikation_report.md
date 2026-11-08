# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-08 15:00 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 9161 |
| Active (180-Tage-Pfad) | 3819367 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-08 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-09 | 2,000 | 0 | 0% |
| 2026-11-10 | 2,000 | 0 | 0% |
| 2026-11-11 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-08 (heute) | 25,970 | 25,967 | 0 | regulaerer Tagesstand |
| 2026-11-09 | 25,367 | 0 | – | noch nicht faellig |
| 2026-11-10 | 32,523 | 0 | – | noch nicht faellig |
| 2026-11-11 | 22,204 | 0 | – | noch nicht faellig |

**Active heute:** 25,967 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **1,001 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,955,620 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-08). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 1,001 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen. **Ausnahme Watchlist mit Tagesdeckel:** Vorhersage und Ist sind hier die am Kalendertag entfernte Menge (max. 2.000, "Muell zuerst" aus dem Rueckstau); eine Rettungsquote ist dann nicht bestimmbar ("–").

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-25 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-10-26 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-10-27 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-10-28 | 2,000 | 7 | – (Tagesdeckel) | – |
| 2026-10-29 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-10-30 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-10-31 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-01 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-02 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-03 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-04 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-05 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-06 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-07 | 2,000 | 2,000 | – (Tagesdeckel) | – |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-25 | 21,450 | 21,449 | 1 | 0.0% |
| 2026-10-26 | 20,152 | 20,148 | 4 | 0.0% |
| 2026-10-27 | 20,360 | 20,356 | 4 | 0.0% |
| 2026-10-28 | 15,457 | 15,453 | 4 | 0.0% |
| 2026-10-29 | 9,468 | 9,465 | 3 | 0.0% |
| 2026-10-30 | 61,481 | 61,477 | 4 | 0.0% |
| 2026-10-31 | 87,983 | 87,983 | 0 | 0.0% |
| 2026-11-01 | 27,681 | 27,680 | 1 | 0.0% |
| 2026-11-02 | 28,622 | 28,619 | 3 | 0.0% |
| 2026-11-03 | 29,561 | 29,555 | 6 | 0.0% |
| 2026-11-04 | 29,404 | 29,401 | 3 | 0.0% |
| 2026-11-05 | 25,089 | 25,084 | 5 | 0.0% |
| 2026-11-06 | 36,119 | 36,118 | 1 | 0.0% |
| 2026-11-07 | 24,295 | 24,291 | 4 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +6,174 (Anstieg) (jetzt 11,187,895 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +129,452 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 812,023 neue IPs hinzugekommen (davon 706,530 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 9 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 109,930 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 4,058,676 (Summe 5 verschiedene Combined-Läufe in den letzten 8 Prüfläufen / ~24h; vor dem Aufnahme-Filter gezählt)
- Entfernte IPs (abgelaufen): heute 27,967 | gestern 26,291 (Kalendertag, aus Ablauf-Ledgern)
  - davon Watchlist/30 Tage: heute 2,000 | gestern 2,000
  - davon Active/180 Tage: heute 25,967 | gestern 24,291
- Netto-Wachstum (~24h): 📉 -4,250 (~24h) ⚠️ **schrumpft aktuell netto** - mehr entfernt als neu aufgenommen
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | 1 sonstige, Zeitraum 2026-11-07T12:50 bis 2026-11-08T13:52 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-05 17:56 CET (Europe/Berlin) | 11,181,445 | 5745 | 3733779 | 0 |
| 2026-11-05 21:26 CET (Europe/Berlin) | 11,190,160 | 5745 | 3733697 | 0 |
| 2026-11-05 23:43 CET (Europe/Berlin) | 11,193,835 | 5745 | 3733673 | 0 |
| 2026-11-06 02:56 CET (Europe/Berlin) | 11,160,395 | 6887 | 3769719 | 0 |
| 2026-11-06 12:28 CET (Europe/Berlin) | 11,180,585 | 6887 | 3769620 | 0 |
| 2026-11-06 12:42 CET (Europe/Berlin) | 11,180,585 | 6887 | 3769620 | 0 |
| 2026-11-06 19:23 CET (Europe/Berlin) | 11,189,196 | 6887 | 3769542 | 0 |
| 2026-11-06 20:46 CET (Europe/Berlin) | 11,192,348 | 6887 | 3769505 | 0 |
| 2026-11-07 00:29 CET (Europe/Berlin) | 11,195,039 | 6887 | 3769467 | 0 |
| 2026-11-07 02:28 CET (Europe/Berlin) | 11,172,501 | 8033 | 3793726 | 0 |
| 2026-11-07 11:46 CET (Europe/Berlin) | 11,185,319 | 8033 | 3793631 | 0 |
| 2026-11-07 11:49 CET (Europe/Berlin) | 11,185,319 | 8033 | 3793631 | 0 |
| 2026-11-07 17:59 CET (Europe/Berlin) | 11,192,145 | 8032 | 3793551 | 0 |
| 2026-11-07 18:54 CET (Europe/Berlin) | 11,192,145 | 8032 | 3793551 | 0 |
| 2026-11-07 21:50 CET (Europe/Berlin) | 11,194,167 | 8032 | 3793527 | 0 |
| 2026-11-07 23:27 CET (Europe/Berlin) | 11,196,864 | 8032 | 3793504 | 0 |
| 2026-11-08 07:46 CET (Europe/Berlin) | 11,181,721 | 9161 | 3819398 | 0 |
| 2026-11-08 07:51 CET (Europe/Berlin) | 11,181,721 | 9161 | 3819398 | 0 |
| 2026-11-08 08:33 CET (Europe/Berlin) | 11,181,721 | 9161 | 3819398 | 0 |
| 2026-11-08 15:00 CET (Europe/Berlin) | 11,187,895 | 9161 | 3819367 | 0 |
