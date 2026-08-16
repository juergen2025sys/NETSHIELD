# Score Decay Monitor – Report
**Aktualisiert:** 2026-08-16 09:31 CEST (Europe/Berlin)

---
## Übersicht

| Kategorie | IPs | Bedeutung |
|---|---|---|
| ✅ Kürzlich aktiv (≤7 Tage) | **865282** | Frische Bedrohungen |
| 🟡 Veraltend – Warnung | **370073** | 30-44 Tage ohne Aktivität, Score≥25 |
| 🔴 Veraltend – Kritisch | **4662830** | 45+ Tage ohne Aktivität, Score≥40 |
| 💀 Zombie | **1916111** | Score≥65, 30+ Tage inaktiv |
| ⏳ Läuft bald ab (150+ Tage) | **841727** | combined entfernt bei 180 Tagen |

---
## ℹ️ Hinweis
Score-Berechnung harmonisiert mit `calculate_confidence` (0-100-Skala).
IPs werden **nicht** durch diesen Workflow gelöscht.
Das Entfernen aus combined + seen_db erfolgt ausschließlich durch
`update_combined_blacklist` nach **180 Tagen** ohne Feed-Bestätigung.

---
*Generiert: 2026-08-16 09:31 CEST (Europe/Berlin) | DB: 9162471 IPs*