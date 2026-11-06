# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-06 12:28 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 6887 |
| Active (180-Tage-Pfad) | 3769620 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-06 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-07 | 2,000 | 0 | 0% |
| 2026-11-08 | 2,000 | 0 | 0% |
| 2026-11-09 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-06 (heute) | 36,119 | 36,118 | 0 | regulaerer Tagesstand |
| 2026-11-07 | 24,295 | 0 | – | noch nicht faellig |
| 2026-11-08 | 25,973 | 0 | – | noch nicht faellig |
| 2026-11-09 | 25,377 | 0 | – | noch nicht faellig |

**Active heute:** 36,118 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **960 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,938,772 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-06). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 960 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-23 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-24 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-25 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-26 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-27 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-28 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-29 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-30 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-31 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-11-01 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-11-02 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-11-03 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-11-04 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-11-05 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-23 | 50,171 | 50,169 | 2 | 0.0% |
| 2026-10-24 | 41,537 | 41,533 | 4 | 0.0% |
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

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +20,190 (Anstieg) (jetzt 11,180,585 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +122,142 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 820,517 neue IPs hinzugekommen (davon 704,769 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 52 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 110,183 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 6,482,943 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 65,206 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 4,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 61,206 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +20,599 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/16 erfolgreich (94%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-11-05T11:32 bis 2026-11-06T11:15 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-11-03 04:13 CET (Europe/Berlin) | 11,166,450 | 3473 | 3680032 | 0 |
| 2026-11-03 11:46 CET (Europe/Berlin) | 11,176,516 | 3473 | 3679957 | 0 |
| 2026-11-03 12:31 CET (Europe/Berlin) | 11,176,516 | 3473 | 3679957 | 0 |
| 2026-11-03 19:25 CET (Europe/Berlin) | 11,182,041 | 3473 | 3679845 | 0 |
| 2026-11-03 20:55 CET (Europe/Berlin) | 11,182,041 | 3473 | 3679845 | 0 |
| 2026-11-04 00:40 CET (Europe/Berlin) | 11,188,227 | 3473 | 3679743 | 0 |
| 2026-11-04 02:47 CET (Europe/Berlin) | 11,158,594 | 4607 | 3709117 | 29403 |
| 2026-11-04 07:01 CET (Europe/Berlin) | 11,162,247 | 4607 | 3709094 | 0 |
| 2026-11-04 12:47 CET (Europe/Berlin) | 11,172,266 | 4607 | 3709044 | 0 |
| 2026-11-04 15:22 CET (Europe/Berlin) | 11,172,266 | 4607 | 3709044 | 0 |
| 2026-11-04 21:11 CET (Europe/Berlin) | 11,181,171 | 4607 | 3708934 | 0 |
| 2026-11-05 02:27 CET (Europe/Berlin) | 11,159,986 | 5745 | 3733964 | 0 |
| 2026-11-05 02:55 CET (Europe/Berlin) | 11,159,986 | 5745 | 3733964 | 0 |
| 2026-11-05 09:29 CET (Europe/Berlin) | 11,167,849 | 5745 | 3733911 | 0 |
| 2026-11-05 12:45 CET (Europe/Berlin) | 11,172,291 | 5745 | 3733846 | 0 |
| 2026-11-05 17:56 CET (Europe/Berlin) | 11,181,445 | 5745 | 3733779 | 0 |
| 2026-11-05 21:26 CET (Europe/Berlin) | 11,190,160 | 5745 | 3733697 | 0 |
| 2026-11-05 23:43 CET (Europe/Berlin) | 11,193,835 | 5745 | 3733673 | 0 |
| 2026-11-06 02:56 CET (Europe/Berlin) | 11,160,395 | 6887 | 3769719 | 0 |
| 2026-11-06 12:28 CET (Europe/Berlin) | 11,180,585 | 6887 | 3769620 | 0 |
