# Score Decay Monitor – Report
**Aktualisiert:** 2026-09-27 14:50 CEST (Europe/Berlin)

---
## Übersicht

| Kategorie | IPs | Bedeutung |
|---|---|---|
| ✅ Kürzlich aktiv (≤7 Tage) | **944450** | Frische Bedrohungen |
| 🟡 Veraltend – Warnung | **816154** | 30-44 Tage ohne Aktivität, Score≥25 |
| 🔴 Veraltend – Kritisch | **3446617** | 45+ Tage ohne Aktivität, Score≥40 |
| 💀 Zombie | **1993915** | Score≥65, 30+ Tage inaktiv |
| ⏳ Läuft bald ab (150+ Tage) | **2536968** | combined entfernt bei 180 Tagen |

---
## ℹ️ Hinweis
Score-Berechnung harmonisiert mit `calculate_confidence` (0-100-Skala).
IPs werden **nicht** durch diesen Workflow gelöscht.
Das Entfernen aus combined + seen_db erfolgt ausschließlich durch
`update_combined_blacklist` nach **180 Tagen** ohne Feed-Bestätigung.

---
*Generiert: 2026-09-27 14:50 CEST (Europe/Berlin) | DB: 11785856 IPs*