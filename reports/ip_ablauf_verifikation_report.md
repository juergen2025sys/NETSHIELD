# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-10 21:39 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 21868 |
| Active (180-Tage-Pfad) | 1371967 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-10 (heute) | 2,000 | 2,000 | 100% |
| 2026-10-11 | 2,000 | 0 | 0% |
| 2026-10-12 | 2,000 | 0 | 0% |
| 2026-10-13 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-10 (heute) | 53,244 | 53,239 | 0 | regulaerer Tagesstand |
| 2026-10-11 | 15,987 | 0 | – | noch nicht faellig |
| 2026-10-12 | 66,482 | 0 | – | noch nicht faellig |
| 2026-10-13 | 1,579,870 | 0 | – | noch nicht faellig |

**Active heute:** 53,239 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **3,512 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,647,247 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-10). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 3,512 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-26 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-27 | 2,000 | 0 | 2,000 | 100.0% |
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

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-26 | 17,410 | 17,399 | 11 | 0.1% |
| 2026-09-27 | 14,989 | 14,978 | 11 | 0.1% |
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

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +4,759 (Anstieg) (jetzt 12,265,633 IPs)
- Seit Zyklus-Start (2026-09-22): 📈 +787,914 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 891,570 neue IPs hinzugekommen (davon 768,406 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 74 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 118,684 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,292,914 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 0 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +29,120 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-09T18:26 bis 2026-10-10T19:32 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-08 02:57 CEST (Europe/Berlin) | 12,400,991 | 16199 | 1038229 | 0 |
| 2026-10-08 03:27 CEST (Europe/Berlin) | 12,400,991 | 16199 | 1038229 | 0 |
| 2026-10-08 09:19 CEST (Europe/Berlin) | 12,354,282 | 18179 | 1099060 | 0 |
| 2026-10-08 13:04 CEST (Europe/Berlin) | 12,362,550 | 18179 | 1099017 | 0 |
| 2026-10-08 16:55 CEST (Europe/Berlin) | 12,370,968 | 18179 | 1098917 | 0 |
| 2026-10-08 21:06 CEST (Europe/Berlin) | 12,377,181 | 18178 | 1098809 | 0 |
| 2026-10-09 03:12 CEST (Europe/Berlin) | 12,179,127 | 20032 | 1319295 | 0 |
| 2026-10-09 03:35 CEST (Europe/Berlin) | 12,179,127 | 20032 | 1319295 | 0 |
| 2026-10-09 10:01 CEST (Europe/Berlin) | 12,191,771 | 20032 | 1319237 | 0 |
| 2026-10-09 13:03 CEST (Europe/Berlin) | 12,208,824 | 20032 | 1319123 | 0 |
| 2026-10-09 17:16 CEST (Europe/Berlin) | 12,213,457 | 20030 | 1319020 | 0 |
| 2026-10-09 20:36 CEST (Europe/Berlin) | 12,231,552 | 20029 | 1318934 | 0 |
| 2026-10-09 22:22 CEST (Europe/Berlin) | 12,236,513 | 20029 | 1318920 | 0 |
| 2026-10-10 00:59 CEST (Europe/Berlin) | 12,247,560 | 20028 | 1318869 | 0 |
| 2026-10-10 08:25 CEST (Europe/Berlin) | 12,210,251 | 21873 | 1372010 | 0 |
| 2026-10-10 08:34 CEST (Europe/Berlin) | 12,210,251 | 21873 | 1372010 | 0 |
| 2026-10-10 15:07 CEST (Europe/Berlin) | 12,251,421 | 21869 | 1371989 | 0 |
| 2026-10-10 15:10 CEST (Europe/Berlin) | 12,251,421 | 21869 | 1371989 | 0 |
| 2026-10-10 19:50 CEST (Europe/Berlin) | 12,260,874 | 21868 | 1371976 | 0 |
| 2026-10-10 21:39 CEST (Europe/Berlin) | 12,265,633 | 21868 | 1371967 | 0 |
