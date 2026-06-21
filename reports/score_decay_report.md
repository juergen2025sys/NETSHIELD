# Score Decay Monitor – Report
**Aktualisiert:** 2026-06-21 10:30 UTC

---
## Übersicht

| Kategorie | IPs | Bedeutung |
|---|---|---|
| ✅ Kürzlich aktiv (≤7 Tage) | **365337** | Frische Bedrohungen |
| 🟡 Veraltend – Warnung | **590557** | 30-44 Tage ohne Aktivität, Score≥25 |
| 🔴 Veraltend – Kritisch | **3627685** | 45+ Tage ohne Aktivität, Score≥40 |
| 💀 Zombie | **1755230** | Score≥65, 30+ Tage inaktiv |
| ⏳ Läuft bald ab (150+ Tage) | **0** | combined entfernt bei 180 Tagen |

---
## ℹ️ Hinweis
Score-Berechnung harmonisiert mit `calculate_confidence` (0-100-Skala).
IPs werden **nicht** durch diesen Workflow gelöscht.
Das Entfernen aus combined + seen_db erfolgt ausschließlich durch
`update_combined_blacklist` nach **180 Tagen** ohne Feed-Bestätigung.

---
*Generiert: 2026-06-21 10:30 UTC | DB: 6486126 IPs*