# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-22 15:24 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 3986 |
| Active (180-Tage-Pfad) | 836845 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-22 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-23 | 2,000 | 0 | 0% |
| 2026-09-24 | 2,000 | 0 | 0% |
| 2026-09-25 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-09-22 (heute) | 6,431 | 6,425 | 0 | regulaerer Tagesstand |
| 2026-09-23 | 13,046 | 0 | – | noch nicht faellig |
| 2026-09-24 | 16,645 | 0 | – | noch nicht faellig |
| 2026-09-25 | 20,918 | 0 | – | noch nicht faellig |

**Active heute:** 6,425 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **3,733 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 593,792 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-22). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 3,733 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-08 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-09 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-10 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-11 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-12 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-13 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-14 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-15 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-16 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-17 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-18 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-19 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-20 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-21 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |
| 2026-09-21 | 6,509 | 0 | 6,509 | 100.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +3,278 (Anstieg) (jetzt 11,516,051 IPs)
- Seit Zyklus-Start (2026-09-22): 📈 +38,332 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 958,831 neue IPs hinzugekommen (davon 828,952 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 124 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 126,841 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 5,774,704 (Summe letzte 6 Läufe / 6 Lauf(e), noch keine 24h Historie seit Zyklus-Start)
- Entfernte IPs (Summe letzter Läufe): 16,860 (Summe letzte 6 Läufe / 6 Lauf(e), noch keine 24h Historie seit Zyklus-Start)
  - davon Watchlist/30 Tage: 4,000 (Summe letzte 6 Läufe / 6 Lauf(e), noch keine 24h Historie seit Zyklus-Start)
  - davon Active/180 Tage: 12,860 (Summe letzte 6 Läufe / 6 Lauf(e), noch keine 24h Historie seit Zyklus-Start)
- Netto-Wachstum (6 Lauf(e), noch keine 24h Historie seit Zyklus-Start): 📈 +38,332 (6 Lauf(e), noch keine 24h Historie seit Zyklus-Start)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-21T19:56 bis 2026-09-22T12:03 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-22 02:27 CEST (Europe/Berlin) | 11,477,719 | 3986 | 837060 | 6430 |
| 2026-09-22 03:50 CEST (Europe/Berlin) | 11,477,719 | 3986 | 837060 | 0 |
| 2026-09-22 07:40 CEST (Europe/Berlin) | 11,493,882 | 3986 | 836983 | 0 |
| 2026-09-22 09:41 CEST (Europe/Berlin) | 11,495,942 | 3986 | 836965 | 0 |
| 2026-09-22 14:14 CEST (Europe/Berlin) | 11,512,773 | 3986 | 836923 | 0 |
| 2026-09-22 15:24 CEST (Europe/Berlin) | 11,516,051 | 3986 | 836845 | 0 |
