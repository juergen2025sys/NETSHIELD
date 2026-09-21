# IP-Ablauf-Verifikationsbericht

Lauf: 2026-09-21 08:13 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 4078 |
| Active (180-Tage-Pfad) | 830752 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-09-21 (heute) | 2,000 | 2,000 | 100% |
| 2026-09-22 | 2,000 | 0 | 0% |
| 2026-09-23 | 2,000 | 0 | 0% |
| 2026-09-24 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-09-21 (heute) | 6,509 | 243,111 | 243,062 | Rueckstau/Altbestand wird abgebaut – kein %-Vergleich |
| 2026-09-22 | 6,434 | 0 | – | noch nicht faellig |
| 2026-09-23 | 13,057 | 0 | – | noch nicht faellig |
| 2026-09-24 | 16,667 | 0 | – | noch nicht faellig |

**Active heute:** 243,111 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 243,062 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **194,867 Treffer sind legitime Active→Watchlist-Wiedereintritte und kein Anti-Churn-Rückfall.** Diese IPs stehen noch im Active-Ledger, wurden aber nur schwach neu bestätigt und erscheinen deshalb in konsolidierten Watchlist/Combined-Ausgaben, nicht jedoch in `active_blacklist_ipv4.txt`. Der eingefrorene Active-Anker bleibt erhalten; erst eine echte starke Neubestätigung darf wieder einen neuen 180-Tage-Active-Pfad starten.

ℹ️ **3,811 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 582,818 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-09-21). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 194,867 legitime Active→Watchlist-Treffer; 3,811 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-07 | 2,000 | 0 | 2,000 | 100.0% |
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

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
| 2026-09-04 | 173,700 | 0 | 173,700 | 100.0% |
| 2026-09-05 | 173,665 | 173,637 | 28 | 0.0% |
| 2026-09-07 | 663,981 | 0 | 663,981 | 100.0% |
| 2026-09-08 | 662,324 | 661,899 | 425 | 0.1% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 11,645,885 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +2,249,846 (Anstieg)
- Letzter combined-Cleanup-Pass: 243,062 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 243,062 Active/180T), 1,077,906 neue IPs hinzugekommen (davon 939,213 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 755 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 130,969 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 8,584,247 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 1,946,674 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 1,944,674 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📈 +24,169 (~24h)
- Erfolgsquote letzte 16 combined-Läufe: 15/15 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt) | zusätzlich 1 cancelled (nicht gewertet), Zeitraum 2026-09-20T16:20 bis 2026-09-21T05:30 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-09-19 13:43 CEST (Europe/Berlin) | 11,537,242 | 4228 | 831238 | 0 |
| 2026-09-19 15:36 CEST (Europe/Berlin) | 11,542,682 | 4228 | 831165 | 0 |
| 2026-09-19 18:11 CEST (Europe/Berlin) | 11,546,231 | 4228 | 831152 | 0 |
| 2026-09-19 21:26 CEST (Europe/Berlin) | 11,560,330 | 4227 | 831075 | 0 |
| 2026-09-19 23:12 CEST (Europe/Berlin) | 11,563,888 | 4227 | 831066 | 0 |
| 2026-09-20 01:48 CEST (Europe/Berlin) | 11,570,463 | 4227 | 831052 | 0 |
| 2026-09-20 07:22 CEST (Europe/Berlin) | 11,584,609 | 4227 | 831001 | 0 |
| 2026-09-20 07:34 CEST (Europe/Berlin) | 11,584,609 | 4227 | 831001 | 0 |
| 2026-09-20 12:11 CEST (Europe/Berlin) | 11,603,678 | 4225 | 830929 | 0 |
| 2026-09-20 13:56 CEST (Europe/Berlin) | 11,603,678 | 4225 | 830929 | 0 |
| 2026-09-20 16:23 CEST (Europe/Berlin) | 11,606,039 | 4225 | 830868 | 0 |
| 2026-09-20 18:39 CEST (Europe/Berlin) | 11,612,057 | 4225 | 830854 | 0 |
| 2026-09-20 22:44 CEST (Europe/Berlin) | 11,621,716 | 4224 | 830833 | 0 |
| 2026-09-20 23:08 CEST (Europe/Berlin) | 11,621,716 | 4224 | 830833 | 0 |
| 2026-09-20 23:10 CEST (Europe/Berlin) | 11,621,716 | 4224 | 830833 | 0 |
| 2026-09-21 01:12 CEST (Europe/Berlin) | 11,622,871 | 4224 | 830823 | 0 |
| 2026-09-21 01:45 CEST (Europe/Berlin) | 11,622,871 | 4224 | 830823 | 0 |
| 2026-09-21 03:34 CEST (Europe/Berlin) | 11,627,828 | 4078 | 830792 | 0 |
| 2026-09-21 07:43 CEST (Europe/Berlin) | 11,645,885 | 4078 | 830752 | 0 |
| 2026-09-21 08:13 CEST (Europe/Berlin) | 11,645,885 | 4078 | 830752 | 0 |
