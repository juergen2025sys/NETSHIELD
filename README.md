
# 🛡️ NETSHIELD

**Automatisiertes IP-Threat-Intelligence-System mit dynamischer Blacklist-Verwaltung**

NETSHIELD aggregiert, bewertet und bereinigt IP-Bedrohungsdaten aus über 130 öffentlichen Feeds.  
Das System trennt aktiv bestätigte Bedrohungen von statischen Listen und erzeugt daraus hochwertige, selbstbereinigende Firewall-Blocklisten.

---

## 🚀 Kernprinzip

- **Nur HQ-Feeds bestimmen die Lebenszeit einer IP**
- **Non-HQ-Feeds erhöhen nur den Confidence-Score**
- **IPs altern automatisch aus (180 Tage)**
- **Reaktivierung erfolgt bei neuer Aktivität**

👉 Das System bereinigt automatisch, was klassische Blocklisten nicht können.

---

## 🧠 Architektur (vereinfacht)

```
HQ-Feeds (Feodo, Talos, Spamhaus, AbuseIPDB)
        ↓ setzt last_seen
Non-HQ-Feeds (Mega-Listen)
        ↓ erhöht feed_count

        → Update Combined Blacklist (8x täglich)
              ↓
     ┌────────┼────────┬────────┐
     ↓        ↓        ↓        ↓
active   confidence40  watchlist  combined
(≥65)     (≥40)        (25–39)    (alle IPs)
```

**Output-Listen:**
- `active_blacklist` → sehr aggressiv (Score ≥65, 30 Tage)
- `blacklist_confidence40` → empfohlene Firewall-Liste
- `watchlist` → neue/unsichere IPs zur Analyse
- `combined_blacklist` → vollständige Historie (Audit/SIEM)

---

## 📊 Blocklisten

| Datei | Beschreibung | Einsatz |
|------|-------------|--------|
| `active_blacklist_ipv4.txt` | Aktive Bedrohungen (Score ≥65, 30 Tage) | Aggressives Blocking |
| `blacklist_confidence40_ipv4.txt` | Mittleres/Hohes Vertrauen (Score ≥40) | ✅ **Empfohlen für Firewall** |
| `watchlist_confidence25to39_ipv4.txt` | Neue/unsichere IPs (Score 25–39) | Monitoring |
| `combined_threat_blacklist_ipv4.txt` | Alle IPs (180 Tage) | Audit / SIEM |

---

## 🔥 Für OPNsense / Firewall

### ✅ Empfohlen (stabil & effektiv)
```
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/blacklist_confidence40_ipv4.txt
```

### ⚠️ Aggressiv (optional)
```
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/active_blacklist_ipv4.txt
```

---

## ⚙️ Scoring-System

Jede IP erhält einen Score von **0–100**:

```
Score = Quellen + Aktualität + Persistenz + Historie
```

| Faktor | Beschreibung |
|--------|------------|
| Quellen | HQ vs Non-HQ |
| Aktualität | letzte Bestätigung |
| Persistenz | Anzahl Tage aktiv |
| Historie | bekannte Lebensdauer |

**Schwellenwerte:**
- ≥65 → `active_blacklist`
- ≥40 → `confidence40`
- 25–39 → `watchlist`
- <25 → nur `combined`

---

## 🔄 Workflows

| Workflow | Aufgabe |
|---------|--------|
| Combined | Hauptengine (Feeds + seen_db) |
| Confidence | Score-Auswertung |
| Honeypot / HoneyDB | reale Angriffe |
| Feed Health | Feed-Überwachung |
| Workflow Health | YAML/Python Checks |
| Score Decay | Alterungsanalyse |
| Geo Tagger | Länder-Zuordnung |
| ASN Scorer | ASN-Risiko |

---

## 🗂️ Struktur

```
NETSHIELD/
├── .github/workflows/
├── active_blacklist_ipv4.txt
├── blacklist_confidence40_ipv4.txt
├── watchlist_confidence25to39_ipv4.txt
├── combined_threat_blacklist_ipv4.txt
├── seen_db_meta.json
├── NETSHIELD_REPORT.md
└── README.md
```

---

## 📈 Besonderheiten

- Selbstheilendes System (keine statischen Leichen)
- Cache-basierte Intelligenz (`seen_db`)
- False-Positive Schutz + Whitelisting
- Multi-Feed Korrelation
- Automatische Qualitätssicherung

---

## 🧾 Reports

- `NETSHIELD_REPORT.md` → Gesamtübersicht
- `feed_health_report.md` → Feed-Status
- `workflow_health_report.md` → Workflow Checks
- `score_decay_report.md` → Alterung

---

## 🤝 Community

IPs können per Issue gemeldet werden:

- werden als `hq=False` aufgenommen
- steigen bei mehrfacher Meldung im Score
- automatische Integration ins System

---

## 🛡️ Fazit

NETSHIELD ist keine klassische Blacklist –  
es ist ein **dynamisches Threat-Intelligence-System** mit:

✔ automatischer Bereinigung  
✔ Kontext-basierter Bewertung  
✔ hoher Signalqualität  

---

*Automatisch generiert und gepflegt durch NETSHIELD*
