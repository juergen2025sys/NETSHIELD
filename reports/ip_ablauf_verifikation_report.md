# IP-Ablauf-Verifikationsbericht

Lauf: 2026-10-24 07:15 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 16782 |
| Active (180-Tage-Pfad) | 3360729 |

## Live-Fortschritt (heute + nächste Tage)

Zwischenstand, aktualisiert bei JEDEM Lauf (alle 3h) - nicht erst wenn der Tag vorbei ist. "Bisher eingefroren" zeigt die tatsaechlich an diesem Kalendertag entfernten IPs. Fuer Watchlist/30T wird zusaetzlich der persistente Tages-Cap-State verwendet, damit ein frueher 2.000er-Lauf nicht durch spaetere Combined-Laeufe mit `expired_watchlist=0` aus der Anzeige verschwindet. Active/180T wird dagegen aus dem Ledger-Feld `eingefroren_am` als eindeutige Tagesmenge gezaehlt. Der Wert des letzten Combined-Laufs wird separat angezeigt und nicht mehr ueber mehrere Laeufe aufsummiert.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Bisher eingefroren | Fortschritt |
|---|---:|---:|---:|
| 2026-10-24 (heute) | 2,000 | 2,000 | 100% |
| 2026-10-25 | 2,000 | 0 | 0% |
| 2026-10-26 | 2,000 | 0 | 0% |
| 2026-10-27 | 2,000 | 0 | 0% |

**Active (180-Tage-Pfad):**

Beim Active-Pfad ist die Prognose die regulaer fuer diesen Tag erwartete Faelligkeits-Kohorte. Wenn gleichzeitig ein alter 180T-Rueckstau abgearbeitet wird, kann die reale Tagesmenge deutlich hoeher sein; deshalb wird in diesem Fall bewusst kein irrefuehrender Prozentwert berechnet.

| Datum | Prognose regulaer faellig | Heute eindeutig neu eingefroren | Letzter Combined-Cleanup | Einordnung |
|---|---:|---:|---:|---|
| 2026-10-24 (heute) | 41,537 | 41,535 | 0 | regulaerer Tagesstand |
| 2026-10-25 | 21,454 | 0 | – | noch nicht faellig |
| 2026-10-26 | 20,158 | 0 | – | noch nicht faellig |
| 2026-10-27 | 20,378 | 0 | – | noch nicht faellig |

**Active heute:** 41,535 eindeutige IPs neu im 180T-Ledger eingefroren; letzter Combined-Lauf: 0 Active-IP(s) als Ablauf entfernt.

## Diagnose-Status

✅ Keine Probleme erkannt (Rückfälle, Ledger-Konsistenz, Datenaktualität).

## Wiederauftauch-Prüfung

ℹ️ **2,122 Treffer sind ein legitimer Watchlist-Tages-Cap-Backlog und kein Anti-Churn-Rückfall.** Der aktuelle Combined-State meldet 2,759,970 noch wartende 30-Tage-Kandidaten (State-Tag: 2026-10-24). Diese IPs stehen im Watchlist-Ledger, aber nicht in `active_blacklist_ipv4.txt`; sie duerfen bis zu einem spaeteren 2.000er-Tages-Slot voruebergehend im Output bleiben.

✅ 0 echte Rückfälle nach Bereinigung - 2,122 erklaerte Watchlist-Cap-Backlog-Treffer. Sonst keine Auffaelligkeit. Der Fix haelt.

## Prognose-Genauigkeit (Vorhersage vs. Realität)

Gleicht die Tages-Vorhersagen aus reports/ip_ablauf.md (Job "prognose") gegen die tatsaechlichen Ledger-Eintraege ab (nach Anker-Datum + Fenster gruppiert, dieselbe Formel wie die jeweilige Prognose: `first`+31 Tage fuer Watchlist, `last`+181 Tage fuer Active), sobald das jeweilige Datum erreicht ist. "Gerettet" = per Zweitbestaetigung (5+ Feeds oder 2+ HQ-Familien) doch nicht abgelaufen.

**Watchlist (30-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-10-21 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-22 | 2,000 | 0 | 2,000 | 100.0% |
| 2026-10-23 | 2,000 | 0 | 2,000 | 100.0% |

_31 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

**Active (180-Tage-Pfad):**

| Datum | Vorhergesagt | Tatsächlich | Gerettet | Rettungsquote |
|---|---:|---:|---:|---:|
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
| 2026-10-21 | 11,006 | 11,003 | 3 | 0.0% |
| 2026-10-22 | 30,437 | 30,435 | 2 | 0.0% |
| 2026-10-23 | 50,171 | 50,169 | 2 | 0.0% |

_61 Tag(e) noch ausstehend (Ablaufdatum liegt noch in der Zukunft)._

## seen_db-Trend

- Seit letztem Lauf: 📈 +9,600 (Anstieg) (jetzt 11,100,673 IPs)
- Seit Zyklus-Start (2026-10-22): 📈 +42,230 (Anstieg)
- Letzter combined-Cleanup-Pass: 0 IPs durch Ablauf entfernt (davon 0 Watchlist/30T, 0 Active/180T), 886,361 neue IPs hinzugekommen (davon 756,433 direkt wieder durch Aufnahme-Filter entfernt: <2 Feeds & kein HQ) | 316 IPs heute per Kreuzbestätigung (2. Feed innerhalb 7 Tage) doch aufgenommen (zusätzlich: 122,653 CIDR-Aggregate)
- Neue IPs (Summe letzter Läufe): 7,102,465 (Summe letzte 8 Läufe / ~24h)
- Entfernte IPs (Summe letzter Läufe): 43,535 (Summe letzte 8 Läufe / ~24h)
  - davon Watchlist/30 Tage: 2,000 (Summe letzte 8 Läufe / ~24h)
  - davon Active/180 Tage: 41,535 (Summe letzte 8 Läufe / ~24h)
- Netto-Wachstum (~24h): 📉 -13,988 (~24h) ⚠️ **schrumpft aktuell netto** - mehr entfernt als neu aufgenommen
- Erfolgsquote letzte 16 combined-Läufe: 16/16 erfolgreich (100%, nur echte Erfolge/Fehlschläge gezählt), Zeitraum 2026-10-23T09:43 bis 2026-10-24T05:03 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-10-22 03:48 CEST (Europe/Berlin) | 11,058,443 | 20784 | 3269550 | 0 |
| 2026-10-22 07:38 CEST (Europe/Berlin) | 11,068,619 | 20784 | 3269522 | 0 |
| 2026-10-22 09:30 CEST (Europe/Berlin) | 11,077,606 | 20784 | 3269501 | 0 |
| 2026-10-22 14:40 CEST (Europe/Berlin) | 11,089,919 | 20784 | 3269462 | 0 |
| 2026-10-22 19:46 CEST (Europe/Berlin) | 11,103,364 | 20784 | 3269384 | 0 |
| 2026-10-22 23:58 CEST (Europe/Berlin) | 11,118,292 | 20784 | 3269307 | 0 |
| 2026-10-23 00:01 CEST (Europe/Berlin) | 11,118,292 | 20784 | 3269307 | 0 |
| 2026-10-23 07:36 CEST (Europe/Berlin) | 11,088,422 | 18782 | 3319424 | 0 |
| 2026-10-23 13:30 CEST (Europe/Berlin) | 11,103,995 | 18782 | 3319359 | 0 |
| 2026-10-23 14:19 CEST (Europe/Berlin) | 11,109,628 | 18782 | 3319339 | 0 |
| 2026-10-23 18:03 CEST (Europe/Berlin) | 11,114,661 | 18782 | 3319301 | 0 |
| 2026-10-23 19:37 CEST (Europe/Berlin) | 11,114,661 | 18782 | 3319301 | 0 |
| 2026-10-23 21:58 CEST (Europe/Berlin) | 11,121,403 | 18782 | 3319272 | 0 |
| 2026-10-23 23:47 CEST (Europe/Berlin) | 11,125,793 | 18782 | 3319248 | 0 |
| 2026-10-24 01:05 CEST (Europe/Berlin) | 11,125,793 | 18782 | 3319248 | 0 |
| 2026-10-24 02:10 CEST (Europe/Berlin) | 11,125,793 | 18782 | 3319248 | 0 |
| 2026-10-24 03:58 CEST (Europe/Berlin) | 11,091,073 | 16782 | 3360755 | 0 |
| 2026-10-24 07:15 CEST (Europe/Berlin) | 11,100,673 | 16782 | 3360729 | 0 |
