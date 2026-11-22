# Score Decay Monitor – Report
**Aktualisiert:** 2026-11-22 16:05 CET (Europe/Berlin)

---
## Übersicht

| Kategorie | IPs | Bedeutung |
|---|---|---|
| ✅ Kürzlich aktiv (≤7 Tage) | **341282** | Frische Bedrohungen |
| 🟡 Veraltend – Warnung | **1180186** | 30-44 Tage ohne Aktivität, Score≥25 |
| 🔴 Veraltend – Kritisch | **4693077** | 45+ Tage ohne Aktivität, Score≥40 |
| 💀 Zombie | **804943** | Score≥65, 30+ Tage inaktiv |
| ⏳ Läuft bald ab (150+ Tage) | **902913** | combined entfernt bei 180 Tagen |

---
## ℹ️ Hinweis
Score-Berechnung harmonisiert mit `calculate_confidence` (0-100-Skala).
IPs werden **nicht** durch diesen Workflow gelöscht.
Das Entfernen aus combined + seen_db erfolgt ausschließlich durch
`update_combined_blacklist` nach **180 Tagen** ohne Feed-Bestätigung.

---
*Generiert: 2026-11-22 16:05 CET (Europe/Berlin) | DB: 11261049 IPs*