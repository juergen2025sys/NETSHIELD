# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-14 19:37 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 15952 |
| Active (180-Tage-Pfad) | 3959533 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-14 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-15 | 2,000 | 0 | 0% |
| 2026-11-16 | 2,000 | 0 | 0% |
| 2026-11-17 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-14 (heute) | 22,797 | 22,797 | 0 | regulaerer Tagesstand |
| 2026-11-15 | 17,366 | 0 | – | noch nicht faellig |
| 2026-11-16 | 17,836 | 0 | – | noch nicht faellig |
| 2026-11-17 | 15,147 | 0 | – | noch nicht faellig |

**Active heute:** 22,797 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **1,023 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 3,015,217 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-14). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 1,023 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen. **Ausnahme Watchlist mit Tagesdeckel:** Vorhersage und Ist sind hier die am Kalendertag entfernte Menge (max. 2.000, "Muell zuerst" aus dem Rueckstau); eine Rettungsquote ist dann nicht bestimmbar ("–").

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-31 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-01 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-02 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-03 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-04 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-05 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-06 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-07 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-08 | 2,000 | 1,149 | – (Tagesdeckel) | – |
| 2026-11-09 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-10 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-11 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-12 | 2,000 | 2,000 | – (Tagesdeckel) | – |
| 2026-11-13 | 2,000 | 1,154 | – (Tagesdeckel) | – |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-31 | 87,983 | 87,983 | 0 | 0.0% |
| 2026-11-01 | 27,681 | 27,680 | 1 | 0.0% |
| 2026-11-02 | 28,622 | 28,619 | 3 | 0.0% |
| 2026-11-03 | 29,561 | 29,555 | 6 | 0.0% |
| 2026-11-04 | 29,404 | 29,401 | 3 | 0.0% |
| 2026-11-05 | 25,089 | 25,084 | 5 | 0.0% |
| 2026-11-06 | 36,119 | 36,118 | 1 | 0.0% |
| 2026-11-07 | 24,295 | 24,291 | 4 | 0.0% |
| 2026-11-08 | 25,970 | 25,966 | 4 | 0.0% |
| 2026-11-09 | 25,366 | 25,361 | 5 | 0.0% |
| 2026-11-10 | 32,519 | 32,513 | 6 | 0.0% |
| 2026-11-11 | 22,188 | 22,182 | 6 | 0.0% |
| 2026-11-12 | 20,378 | 20,376 | 2 | 0.0% |
| 2026-11-13 | 19,523 | 19,521 | 2 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +2,219 (Anstieg) (jetzt 11,336,028 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +277,585 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 822,162 neue IPs hinzugekommen (davon 715,216 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 182 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 105,830 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 5,746,709 (Summe 7 verschiedene Combined-Läufe in den letzten 8 Prüfläufen / ~24h; vor dem Aufnahme-Filter gezählt)
- Entfernte IPs (abgelaufen): heute 24,797 | gestern 20,674 (Kalendertag, aus Ablauf-Ledgern)
  - davon Watchlist/30 Tage: heute 2,000 | gestern 1,154
  - davon Active/180 Tage: heute 22,797 | gestern 19,520
- Netto-Wachstum (~24h): 📈 +10,126 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-11-13T20:03 bis 2026-11-14T18:29 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-11 17:06 CET (Europe/Berlin) | 11,260,037 | 12556 | 3897996 | 0 |
| 2026-11-11 18:36 CET (Europe/Berlin) | 11,266,952 | 12556 | 3897938 | 0 |
| 2026-11-12 00:01 CET (Europe/Berlin) | 11,274,995 | 12556 | 3897841 | 0 |
| 2026-11-12 02:12 CET (Europe/Berlin) | 11,256,860 | 13703 | 3918186 | 20377 |
| 2026-11-12 04:49 CET (Europe/Berlin) | 11,256,860 | 13703 | 3918186 | 0 |
| 2026-11-12 13:00 CET (Europe/Berlin) | 11,273,827 | 13699 | 3918040 | 0 |
| 2026-11-12 21:27 CET (Europe/Berlin) | 11,299,112 | 13699 | 3917839 | 0 |
| 2026-11-12 21:34 CET (Europe/Berlin) | 11,299,112 | 13699 | 3917839 | 0 |
| 2026-11-13 02:30 CET (Europe/Berlin) | 11,294,120 | 14824 | 3937249 | 0 |
| 2026-11-13 03:18 CET (Europe/Berlin) | 11,294,120 | 14824 | 3937249 | 0 |
| 2026-11-13 09:45 CET (Europe/Berlin) | 11,305,931 | 14822 | 3937141 | 0 |
| 2026-11-13 12:46 CET (Europe/Berlin) | 11,310,584 | 14821 | 3937087 | 0 |
| 2026-11-13 18:11 CET (Europe/Berlin) | 11,325,902 | 14821 | 3937002 | 0 |
| 2026-11-13 21:12 CET (Europe/Berlin) | 11,330,730 | 14821 | 3936960 | 0 |
| 2026-11-13 23:52 CET (Europe/Berlin) | 11,334,522 | 14821 | 3936910 | 0 |
| 2026-11-14 02:55 CET (Europe/Berlin) | 11,312,273 | 15955 | 3959675 | 0 |
| 2026-11-14 11:54 CET (Europe/Berlin) | 11,329,277 | 15954 | 3959584 | 0 |
| 2026-11-14 12:07 CET (Europe/Berlin) | 11,329,277 | 15954 | 3959584 | 0 |
| 2026-11-14 18:01 CET (Europe/Berlin) | 11,333,809 | 15953 | 3959547 | 0 |
| 2026-11-14 19:37 CET (Europe/Berlin) | 11,336,028 | 15952 | 3959533 | 0 |
