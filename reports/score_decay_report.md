# Score Decay Monitor – Report
**Aktualisiert:** 2026-11-15 15:33 CET (Europe/Berlin)

---
## Übersicht

| Kategorie | IPs | Bedeutung |
|---|---|---|
| ✅ Kürzlich aktiv (≤7 Tage) | **460163** | Frische Bedrohungen |
| 🟡 Veraltend – Warnung | **1260561** | 30-44 Tage ohne Aktivität, Score≥25 |
| 🔴 Veraltend – Kritisch | **4395204** | 45+ Tage ohne Aktivität, Score≥40 |
| 💀 Zombie | **792839** | Score≥65, 30+ Tage inaktiv |
| ⏳ Läuft bald ab (150+ Tage) | **1087061** | combined entfernt bei 180 Tagen |

---
## ℹ️ Hinweis
Score-Berechnung harmonisiert mit `calculate_confidence` (0-100-Skala).
IPs werden **nicht** durch diesen Workflow gelöscht.
Das Entfernen aus combined + seen_db erfolgt ausschließlich durch
`update_combined_blacklist` nach **180 Tagen** ohne Feed-Bestätigung.

---
*Generiert: 2026-11-15 15:33 CET (Europe/Berlin) | DB: 11354029 IPs*