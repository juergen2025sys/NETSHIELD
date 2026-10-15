# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-15 19:32 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 29982 |
| Active (180-Tage-Pfad) | 3107273 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-15 (heute) | 2,000 | 2,000 | 100% |
| 2026-10-16 | 2,000 | 0 | 0% |
| 2026-10-17 | 2,000 | 0 | 0% |
| 2026-10-18 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-15 (heute) | 41,267 | 41,264 | 0 | regulaerer Tagesstand |
| 2026-10-16 | 51,128 | 0 | – | noch nicht faellig |
| 2026-10-17 | 24,154 | 0 | – | noch nicht faellig |
| 2026-10-18 | 14,160 | 0 | – | noch nicht faellig |

**Active heute:** 41,264 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **1,963 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,670,471 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-15). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 1,963 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-10-12 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-13 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-14 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-10-12 | 66,480 | 66,477 | 3 | 0.0% |
| 2026-10-13 | 1,579,746 | 1,579,622 | 124 | 0.0% |
| 2026-10-14 | 32,901 | 32,898 | 3 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +6,575 (Anstieg) (jetzt 10,826,191 IPs)
- Seit Zyklus-Start (2026-09-22): 📉 -651,528 (Rückgang)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 890,222 neue IPs hinzugekommen (davon 763,691 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 35 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 119,966 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,150,710 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 0 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +16,170 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-14T21:33 bis 2026-10-15T17:21 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-12 21:32 CEST (Europe/Berlin) | 12,303,301 | 24526 | 1454106 | 0 |
| 2026-10-13 03:38 CEST (Europe/Berlin) | 10,731,401 | 26359 | 3033744 | 0 |
| 2026-10-13 04:47 CEST (Europe/Berlin) | 10,731,401 | 26359 | 3033744 | 0 |
| 2026-10-13 11:21 CEST (Europe/Berlin) | 10,745,406 | 26359 | 3033698 | 0 |
| 2026-10-13 13:19 CEST (Europe/Berlin) | 10,761,774 | 26359 | 3033642 | 0 |
| 2026-10-13 19:09 CEST (Europe/Berlin) | 10,777,172 | 26359 | 3033581 | 0 |
| 2026-10-13 21:41 CEST (Europe/Berlin) | 10,777,172 | 26359 | 3033509 | 0 |
| 2026-10-14 02:47 CEST (Europe/Berlin) | 10,769,450 | 28174 | 3066341 | 32900 |
| 2026-10-14 03:09 CEST (Europe/Berlin) | 10,769,450 | 28174 | 3066341 | 0 |
| 2026-10-14 07:40 CEST (Europe/Berlin) | 10,771,391 | 28173 | 3066320 | 0 |
| 2026-10-14 14:35 CEST (Europe/Berlin) | 10,795,874 | 28173 | 3066248 | 0 |
| 2026-10-14 19:42 CEST (Europe/Berlin) | 10,803,827 | 28173 | 3066221 | 0 |
| 2026-10-14 23:37 CEST (Europe/Berlin) | 10,810,021 | 28173 | 3066208 | 0 |
| 2026-10-14 23:59 CEST (Europe/Berlin) | 10,819,046 | 28173 | 3066179 | 0 |
| 2026-10-15 07:07 CEST (Europe/Berlin) | 10,793,337 | 29985 | 3107397 | 0 |
| 2026-10-15 07:25 CEST (Europe/Berlin) | 10,793,337 | 29985 | 3107397 | 0 |
| 2026-10-15 12:19 CEST (Europe/Berlin) | 10,816,071 | 29984 | 3107349 | 0 |
| 2026-10-15 14:21 CEST (Europe/Berlin) | 10,819,616 | 29984 | 3107315 | 0 |
| 2026-10-15 17:22 CEST (Europe/Berlin) | 10,819,616 | 29984 | 3107315 | 0 |
| 2026-10-15 19:32 CEST (Europe/Berlin) | 10,826,191 | 29982 | 3107273 | 0 |
