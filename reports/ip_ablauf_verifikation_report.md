# IP-Ablauf-Verifikationsbericht

Lauf: 2026-08-23 18:16 CEST (Europe/Berlin)

Prueft, ob IPs, die einmal ohne Zweitbestaetigung abgelaufen sind (FIX CHURN-WATCHLIST / FIX CHURN-ACTIVE), tatsaechlich dauerhaft draussen bleiben statt Stunden spaeter mit zurueckgesetzter Uhr wieder aufzutauchen.

## Größe der Ablauf-Listen (aktuell eingefrorene IPs)

| Liste | Anzahl |
|---|---:|
| Watchlist (30-Tage-Pfad) | 0 |
| Active (180-Tage-Pfad) | 0 |

## Diagnose-Status

❌ **1 Problem(e) erkannt:**

- ⚠️ **Niedrige combined-Erfolgsquote:** nur 10/16 erfolgreich (62%), Zeitraum 2026-08-23T07:20 bis 2026-08-23T15:58 UTC in den letzten 16 Läufen (Schwelle: 75%) - auch wenn der neueste Stand frisch wirkt, lief das System zuletzt nicht zuverlässig.

## Wiederauftauch-Prüfung

ℹ️ Noch keine IPs in den Ablauf-Listen - entweder ist der Fix noch nicht lange genug aktiv, oder es ist noch keine IP ohne Zweitbestaetigung abgelaufen. Keine Pruefung moeglich, bis der erste Ablauf passiert ist (siehe reports/ip_ablauf.md fuer die naechsten Ablauftermine, z.B. 2026-09-04).

## seen_db-Trend

- Seit letztem Lauf: ➡️ unverändert (jetzt 9,406,053 IPs)
- Seit Zyklus-Start (2026-08-23): 📈 +10,014 (Anstieg)
- Letzter combined-Cleanup-Pass: n/a (kein combined-Lauf mit Cleanup-Statistik gefunden)
- Neue IPs (Summe letzter Läufe): n/a (0/7 Läufe im Fenster mit Daten)
- Entfernte IPs (Summe letzter Läufe): n/a (0/7 Läufe im Fenster mit Daten)
- Erfolgsquote letzte 16 combined-Läufe: 🔍 10/16 erfolgreich (62%), Zeitraum 2026-08-23T07:20 bis 2026-08-23T15:58 UTC

## Verlauf (letzte 20 Läufe)

| Zeitpunkt | seen_db gesamt | Watchlist-Liste | Active-Liste | Rückfälle |
|---|---:|---:|---:|---:|
| 2026-08-23 12:54 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 13:25 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 13:29 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 14:03 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 15:26 CEST (Europe/Berlin) | 9,396,039 | 0 | 0 | 0 |
| 2026-08-23 17:29 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
| 2026-08-23 18:16 CEST (Europe/Berlin) | 9,406,053 | 0 | 0 | 0 |
