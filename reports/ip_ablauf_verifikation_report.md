# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-21 19:48 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 22784 |
| Active (180-Tage-Pfad) | 3239194 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-21 (heute) | 2,000 | 2,000 | 100% |
| 2026-10-22 | 2,000 | 0 | 0% |
| 2026-10-23 | 2,000 | 0 | 0% |
| 2026-10-24 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-21 (heute) | 11,006 | 11,004 | 0 | regulaerer Tagesstand |
| 2026-10-22 | 30,438 | 0 | – | noch nicht faellig |
| 2026-10-23 | 50,180 | 0 | – | noch nicht faellig |
| 2026-10-24 | 41,548 | 0 | – | noch nicht faellig |

**Active heute:** 11,004 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **2,119 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,722,980 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-21). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 2,119 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-07 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-08 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-09 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-10 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-11 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-12 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-13 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-14 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-15 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-16 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-17 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-18 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-19 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-20 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-07 | 14,942 | 14,928 | 14 | 0.1% |
| 2026-10-08 | 60,917 | 60,866 | 51 | 0.1% |
| 2026-10-09 | 220,692 | 220,508 | 184 | 0.1% |
| 2026-10-10 | 53,244 | 53,239 | 5 | 0.0% |
| 2026-10-11 | 15,987 | 15,987 | 0 | 0.0% |
| 2026-10-12 | 66,480 | 66,477 | 3 | 0.0% |
| 2026-10-13 | 1,579,746 | 1,579,622 | 124 | 0.0% |
| 2026-10-14 | 32,901 | 32,898 | 3 | 0.0% |
| 2026-10-15 | 41,267 | 41,263 | 4 | 0.0% |
| 2026-10-16 | 51,126 | 51,121 | 5 | 0.0% |
| 2026-10-17 | 24,149 | 24,147 | 2 | 0.0% |
| 2026-10-18 | 14,154 | 14,152 | 2 | 0.0% |
| 2026-10-19 | 21,951 | 21,944 | 7 | 0.0% |
| 2026-10-20 | 11,053 | 11,052 | 1 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +2,785 (Anstieg) (jetzt 11,064,134 IPs)
- Seit Zyklus-Start (2026-09-22): 📉 -413,585 (Rückgang)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 886,502 neue IPs hinzugekommen (davon 764,458 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 175 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 119,583 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,135,856 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 13,006 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 11,006 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +47,924 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-20T21:53 bis 2026-10-21T17:40 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-19 07:15 CEST (Europe/Berlin) | 10,916,527 | 26783 | 3217832 | 0 |
| 2026-10-19 07:33 CEST (Europe/Berlin) | 10,916,527 | 26783 | 3217832 | 0 |
| 2026-10-19 13:12 CEST (Europe/Berlin) | 10,945,607 | 26783 | 3217768 | 0 |
| 2026-10-19 16:13 CEST (Europe/Berlin) | 10,946,734 | 26783 | 3217721 | 0 |
| 2026-10-19 19:47 CEST (Europe/Berlin) | 10,957,698 | 26783 | 3217677 | 0 |
| 2026-10-19 22:48 CEST (Europe/Berlin) | 10,961,508 | 26783 | 3217664 | 0 |
| 2026-10-20 02:51 CEST (Europe/Berlin) | 10,962,014 | 24784 | 3228669 | 0 |
| 2026-10-20 07:37 CEST (Europe/Berlin) | 10,976,043 | 24784 | 3228628 | 0 |
| 2026-10-20 14:07 CEST (Europe/Berlin) | 10,999,421 | 24784 | 3228569 | 0 |
| 2026-10-20 14:27 CEST (Europe/Berlin) | 10,999,421 | 24784 | 3228569 | 0 |
| 2026-10-20 19:32 CEST (Europe/Berlin) | 11,009,379 | 24784 | 3228499 | 0 |
| 2026-10-20 19:40 CEST (Europe/Berlin) | 11,009,379 | 24784 | 3228499 | 0 |
| 2026-10-20 22:54 CEST (Europe/Berlin) | 11,016,210 | 24784 | 3228437 | 0 |
| 2026-10-21 00:00 CEST (Europe/Berlin) | 11,016,210 | 24784 | 3228437 | 0 |
| 2026-10-21 06:28 CEST (Europe/Berlin) | 11,013,636 | 22784 | 3239361 | 0 |
| 2026-10-21 07:36 CEST (Europe/Berlin) | 11,033,256 | 22784 | 3239326 | 0 |
| 2026-10-21 11:37 CEST (Europe/Berlin) | 11,045,959 | 22784 | 3239315 | 0 |
| 2026-10-21 14:36 CEST (Europe/Berlin) | 11,057,936 | 22784 | 3239256 | 0 |
| 2026-10-21 17:05 CEST (Europe/Berlin) | 11,061,349 | 22784 | 3239226 | 0 |
| 2026-10-21 19:48 CEST (Europe/Berlin) | 11,064,134 | 22784 | 3239194 | 0 |
