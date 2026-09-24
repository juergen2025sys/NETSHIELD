# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-24 19:40 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 3869 |
| Active (180-Tage-Pfad) | 865867 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-24 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-25 | 2,000 | 0 | 0% |
| 2026-09-26 | 2,000 | 0 | 0% |
| 2026-09-27 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-09-24 (heute) | 16,629 | 16,621 | 0 | regulaerer Tagesstand |
| 2026-09-25 | 20,902 | 0 | – | noch nicht faellig |
| 2026-09-26 | 17,419 | 0 | – | noch nicht faellig |
| 2026-09-27 | 15,010 | 0 | – | noch nicht faellig |

**Active heute:** 16,621 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **3,662 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 609,523 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-24). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 3,662 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-09-22 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-09-23 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |
| 2026-09-21 | 6,509 | 0 | 6,509 | 100.0% |
| 2026-09-22 | 6,431 | 6,424 | 7 | 0.1% |
| 2026-09-23 | 13,041 | 13,030 | 11 | 0.1% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 11,645,868 IPs)
- Seit Zyklus-Start (2026-09-22): 📈 +168,149 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 950,605 neue IPs hinzugekommen (davon 827,069 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 1 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 123,347 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,559,351 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 0 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 0 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 0 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +47,202 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-09-24T04:34 bis 2026-09-24T17:33 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-22 14:14 CEST (Europe/Berlin) | 11,512,773 | 3986 | 836923 | 0 |
| 2026-09-22 15:24 CEST (Europe/Berlin) | 11,516,051 | 3986 | 836845 | 0 |
| 2026-09-22 19:28 CEST (Europe/Berlin) | 11,524,945 | 3986 | 836801 | 0 |
| 2026-09-22 23:14 CEST (Europe/Berlin) | 11,528,125 | 3986 | 836790 | 0 |
| 2026-09-22 23:44 CEST (Europe/Berlin) | 11,533,264 | 3984 | 836735 | 0 |
| 2026-09-23 01:48 CEST (Europe/Berlin) | 11,533,264 | 3984 | 836735 | 0 |
| 2026-09-23 01:56 CEST (Europe/Berlin) | 11,533,264 | 3984 | 836735 | 0 |
| 2026-09-23 06:34 CEST (Europe/Berlin) | 11,537,271 | 3984 | 836722 | 0 |
| 2026-09-23 07:24 CEST (Europe/Berlin) | 11,535,965 | 3946 | 849733 | 0 |
| 2026-09-23 11:33 CEST (Europe/Berlin) | 11,545,976 | 3946 | 849711 | 0 |
| 2026-09-23 14:28 CEST (Europe/Berlin) | 11,559,763 | 3946 | 849623 | 0 |
| 2026-09-23 16:29 CEST (Europe/Berlin) | 11,594,263 | 3946 | 849562 | 0 |
| 2026-09-23 19:37 CEST (Europe/Berlin) | 11,598,666 | 3946 | 849549 | 0 |
| 2026-09-23 23:55 CEST (Europe/Berlin) | 11,607,770 | 3943 | 849498 | 0 |
| 2026-09-24 02:19 CEST (Europe/Berlin) | 11,613,648 | 3943 | 849480 | 0 |
| 2026-09-24 07:42 CEST (Europe/Berlin) | 11,607,045 | 3875 | 866077 | 0 |
| 2026-09-24 14:12 CEST (Europe/Berlin) | 11,624,524 | 3871 | 865986 | 0 |
| 2026-09-24 14:27 CEST (Europe/Berlin) | 11,624,524 | 3871 | 865986 | 0 |
| 2026-09-24 19:34 CEST (Europe/Berlin) | 11,645,868 | 3869 | 865867 | 0 |
| 2026-09-24 19:40 CEST (Europe/Berlin) | 11,645,868 | 3869 | 865867 | 0 |
