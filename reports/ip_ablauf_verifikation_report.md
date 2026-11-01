# IP-Ablauf-Verifikationsbericht

Lauf: 2026-11-01 23:33 CET (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 2476 |
| Active (180-Tage-Pfad) | 3622188 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-11-01 (heute) | 2,000 | 2,000 | 100% |
| 2026-11-02 | 2,000 | 0 | 0% |
| 2026-11-03 | 2,000 | 0 | 0% |
| 2026-11-04 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-11-01 (heute) | 27,681 | 27,680 | 0 | regulaerer Tagesstand |
| 2026-11-02 | 28,622 | 0 | – | noch nicht faellig |
| 2026-11-03 | 29,562 | 0 | – | noch nicht faellig |
| 2026-11-04 | 29,418 | 0 | – | noch nicht faellig |

**Active heute:** 27,680 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **2,102 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,886,922 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-11-01). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 2,102 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-18 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-19 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-20 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-21 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-22 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-23 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-24 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-25 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-26 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-27 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-28 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-29 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-30 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-31 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-10-18 | 14,154 | 14,152 | 2 | 0.0% |
| 2026-10-19 | 21,951 | 21,944 | 7 | 0.0% |
| 2026-10-20 | 11,053 | 11,052 | 1 | 0.0% |
| 2026-10-21 | 11,006 | 11,003 | 3 | 0.0% |
| 2026-10-22 | 30,437 | 30,435 | 2 | 0.0% |
| 2026-10-23 | 50,171 | 50,169 | 2 | 0.0% |
| 2026-10-24 | 41,537 | 41,533 | 4 | 0.0% |
| 2026-10-25 | 21,450 | 21,449 | 1 | 0.0% |
| 2026-10-26 | 20,152 | 20,148 | 4 | 0.0% |
| 2026-10-27 | 20,360 | 20,356 | 4 | 0.0% |
| 2026-10-28 | 15,457 | 15,453 | 4 | 0.0% |
| 2026-10-29 | 9,468 | 9,465 | 3 | 0.0% |
| 2026-10-30 | 61,481 | 61,477 | 4 | 0.0% |
| 2026-10-31 | 87,983 | 87,983 | 0 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +2,500 (Anstieg) (jetzt 11,179,558 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +121,115 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 821,762 neue IPs hinzugekommen (davon 697,124 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 156 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 122,319 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 6,798,133 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 29,681 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 27,681 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +7,712 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | 1 sonstige, Zeitraum 2026-11-01T00:01 bis 2026-11-01T22:26 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-30 00:03 CET (Europe/Berlin) | 11,254,564 | 6776 | 3445722 | 0 |
| 2026-10-30 02:52 CET (Europe/Berlin) | 11,193,783 | 4776 | 3507176 | 0 |
| 2026-10-30 07:40 CET (Europe/Berlin) | 11,193,783 | 4776 | 3507176 | 0 |
| 2026-10-30 09:32 CET (Europe/Berlin) | 11,204,068 | 4776 | 3507144 | 0 |
| 2026-10-30 14:44 CET (Europe/Berlin) | 11,215,479 | 4776 | 3507093 | 0 |
| 2026-10-30 21:08 CET (Europe/Berlin) | 11,225,818 | 4776 | 3506999 | 0 |
| 2026-10-30 21:18 CET (Europe/Berlin) | 11,225,818 | 4776 | 3506999 | 0 |
| 2026-10-31 01:03 CET (Europe/Berlin) | 11,231,656 | 4776 | 3506971 | 0 |
| 2026-10-31 02:17 CET (Europe/Berlin) | 11,144,718 | 2776 | 3594920 | 87983 |
| 2026-10-31 06:30 CET (Europe/Berlin) | 11,153,902 | 2776 | 3594906 | 0 |
| 2026-10-31 11:04 CET (Europe/Berlin) | 11,157,585 | 2776 | 3594892 | 0 |
| 2026-10-31 17:22 CET (Europe/Berlin) | 11,171,846 | 2776 | 3594802 | 0 |
| 2026-10-31 18:27 CET (Europe/Berlin) | 11,171,846 | 2776 | 3594802 | 0 |
| 2026-10-31 21:18 CET (Europe/Berlin) | 11,175,258 | 2776 | 3594779 | 0 |
| 2026-10-31 23:06 CET (Europe/Berlin) | 11,177,111 | 2776 | 3594763 | 0 |
| 2026-11-01 06:48 CET (Europe/Berlin) | 11,149,703 | 2477 | 3622427 | 0 |
| 2026-11-01 08:01 CET (Europe/Berlin) | 11,156,973 | 2477 | 3622399 | 0 |
| 2026-11-01 14:09 CET (Europe/Berlin) | 11,164,109 | 2477 | 3622350 | 0 |
| 2026-11-01 17:31 CET (Europe/Berlin) | 11,177,058 | 2476 | 3622262 | 0 |
| 2026-11-01 23:33 CET (Europe/Berlin) | 11,179,558 | 2476 | 3622188 | 0 |
