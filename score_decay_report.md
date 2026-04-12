# Score Decay Monitor – Report
**Aktualisiert:** 2026-04-12 08:03 UTC

---
## Übersicht

| Kategorie | IPs | Bedeutung |
|---|---|---|
| ✅ Kürzlich aktiv (≤7 Tage) | **2478831** | Frische Bedrohungen |
| 🟡 Veraltend – Warnung | **424084** | 30-44 Tage ohne Aktivität |
| 🔴 Veraltend – Kritisch | **0** | 45+ Tage ohne Aktivität |
| 💀 Zombie | **424084** | Score≥20, 30+ Tage inaktiv |
| ⏳ Läuft bald ab (150+ Tage) | **0** | combined entfernt bei 180 Tagen |

---
## ℹ️ Hinweis
IPs werden **nicht** durch diesen Workflow gelöscht.
Das Entfernen aus combined + seen_db erfolgt ausschließlich durch
`update_combined_blacklist` nach **180 Tagen** ohne Feed-Bestätigung.

---
*Generiert: 2026-04-12 08:03 UTC | DB: 4384331 IPs*