# Score Decay Monitor – Report
**Aktualisiert:** 2026-03-29 07:52 UTC

---
## Übersicht

| Kategorie | IPs | Bedeutung |
|---|---|---|
| ✅ Kürzlich aktiv (≤7 Tage) | **2272020** | Frische Bedrohungen |
| 🟡 Veraltend – Warnung | **0** | 30-44 Tage ohne Aktivität |
| 🔴 Veraltend – Kritisch | **0** | 45+ Tage ohne Aktivität |
| 💀 Zombie | **0** | Score≥20, 30+ Tage inaktiv |
| ⏳ Läuft bald ab (150+ Tage) | **693464** | combined entfernt bei 180 Tagen |

---
## ℹ️ Hinweis
IPs werden **nicht** durch diesen Workflow gelöscht.
Das Entfernen aus combined + seen_db erfolgt ausschließlich durch
`update_combined_blacklist` nach **180 Tagen** ohne Feed-Bestätigung.

---
*Generiert: 2026-03-29 07:52 UTC | DB: 3936906 IPs*