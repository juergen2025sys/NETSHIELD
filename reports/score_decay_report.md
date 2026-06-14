# Score Decay Monitor – Report
**Aktualisiert:** 2026-06-14 10:25 UTC

---
## Übersicht

| Kategorie | IPs | Bedeutung |
|---|---|---|
| ✅ Kürzlich aktiv (≤7 Tage) | **435133** | Frische Bedrohungen |
| 🟡 Veraltend – Warnung | **588958** | 30-44 Tage ohne Aktivität, Score≥25 |
| 🔴 Veraltend – Kritisch | **3336188** | 45+ Tage ohne Aktivität, Score≥40 |
| 💀 Zombie | **1749571** | Score≥65, 30+ Tage inaktiv |
| ⏳ Läuft bald ab (150+ Tage) | **0** | combined entfernt bei 180 Tagen |

---
## ℹ️ Hinweis
Score-Berechnung harmonisiert mit `calculate_confidence` (0-100-Skala).
IPs werden **nicht** durch diesen Workflow gelöscht.
Das Entfernen aus combined + seen_db erfolgt ausschließlich durch
`update_combined_blacklist` nach **180 Tagen** ohne Feed-Bestätigung.

---
*Generiert: 2026-06-14 10:25 UTC | DB: 6315881 IPs*