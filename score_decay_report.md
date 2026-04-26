# Score Decay Monitor – Report
**Aktualisiert:** 2026-04-26 08:57 UTC

---
## Übersicht

| Kategorie | IPs | Bedeutung |
|---|---|---|
| ✅ Kürzlich aktiv (≤7 Tage) | **436882** | Frische Bedrohungen |
| 🟡 Veraltend – Warnung | **227404** | 30-44 Tage ohne Aktivität, Score≥25 |
| 🔴 Veraltend – Kritisch | **483932** | 45+ Tage ohne Aktivität, Score≥40 |
| 💀 Zombie | **0** | Score≥65, 30+ Tage inaktiv |
| ⏳ Läuft bald ab (150+ Tage) | **0** | combined entfernt bei 180 Tagen |

---
## ℹ️ Hinweis
Score-Berechnung harmonisiert mit `calculate_confidence` (0-100-Skala).
IPs werden **nicht** durch diesen Workflow gelöscht.
Das Entfernen aus combined + seen_db erfolgt ausschließlich durch
`update_combined_blacklist` nach **180 Tagen** ohne Feed-Bestätigung.

---
*Generiert: 2026-04-26 08:57 UTC | DB: 4645558 IPs*