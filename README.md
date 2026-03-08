
<div align="center">

# 🛡️ NETSHIELD

### Vollständige IPv4-Blocklist-Suite für Firewalls & Netzwerksicherheit

![IPv4](https://img.shields.io/badge/IPv4-254%2C556%20Ranges-blue?style=flat-square)
![Länder](https://img.shields.io/badge/L%C3%A4nder-249-green?style=flat-square)
![Kontinente](https://img.shields.io/badge/Kontinente-6-orange?style=flat-square)
![Update](https://img.shields.io/badge/Update-Automatisch-brightgreen?style=flat-square)
![Lizenz](https://img.shields.io/badge/Lizenz-Kostenlos-lightgrey?style=flat-square)

*Entwickelt für OPNsense · pfSense · FortiGate · und jede Firewall mit IP-Blocklist-Unterstützung*

</div>

---

## 📌 Übersicht

NETSHIELD bietet fertige IPv4-Blocklisten, organisiert nach Land, Kontinent und Bedrohungsstufe. Alle Listen werden vollautomatisch aktualisiert und sind als Raw-Links verfügbar — einfach in die Firewall einfügen und vergessen.

---

## 🌍 Alle Länder

| Eigenschaft | Wert |
|---|---|
| **Einträge** | ~254.556 CIDR-Ranges |
| **Format** | CIDR (z.B. `1.0.0.0/24`) |
| **Update** | Automatisch |
| **Raw Link** | [all_countries_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/all_countries_ipv4.txt) |

**Verwendungszweck:** Blockiert den gesamten eingehenden WAN-Verkehr aus allen Ländern der Welt mit einer einzigen Liste. Ideal für Firewalls, bei denen keine eingehenden Verbindungen benötigt werden — eliminiert die Angriffsfläche durch ausländische IPs vollständig.

---

## 🌐 Kontinent-Blocklisten

Ganze Regionen mit einem einzigen Link blockieren.

| Kontinent | Raw Link |
|---|---|
| 🇪🇺 Europa | [europe_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/continents/europe_ipv4.txt) |
| 🌏 Asien | [asia_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/continents/asia_ipv4.txt) |
| 🌍 Afrika | [africa_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/continents/africa_ipv4.txt) |
| 🌎 Nordamerika | [north_america_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/continents/north_america_ipv4.txt) |
| 🌎 Südamerika | [south_america_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/continents/south_america_ipv4.txt) |
| 🌊 Ozeanien | [oceania_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/continents/oceania_ipv4.txt) |

---

## 🗺️ Länder-Blocklisten

Einzelne Länder blockieren — nach Kontinent organisiert. Den Raw-Link direkt in der Firewall verwenden.

**Raw-Link-Schema:**
```
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/countries/{kontinent}/{land}_ipv4.txt
```

**Beispiele:**
| Land | Raw Link |
|---|---|
| 🇮🇷 Iran | [iran_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/countries/asia/iran_ipv4.txt) |
| 🇨🇳 China | [china_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/countries/asia/china_ipv4.txt) |
| 🇷🇺 Russland | [russia_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/countries/europe/russia_ipv4.txt) |
| 🇺🇸 USA | [united_states_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/countries/north_america/united_states_ipv4.txt) |
| 🇧🇷 Brasilien | [brazil_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/countries/south_america/brazil_ipv4.txt) |
| 🇳🇬 Nigeria | [nigeria_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/countries/africa/nigeria_ipv4.txt) |

> Alle 249 Länderdateien im [`countries/`](https://github.com/juergen2025sys/NETSHIELD/tree/main/countries) Ordner durchsuchen.

---

## 🚫 Threat-Intelligence-Listen

### Blacklist — Hohe Konfidenz (≥ 40%)

| Eigenschaft | Wert |
|---|---|
| **Inhalt** | Bestätigte bösartige IPs mit Konfidenzniveau ≥ 40% |
| **Format** | Eine IP pro Zeile |
| **Update** | Automatisch · Täglich |
| **Raw Link** | [blacklist_confidence40_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/blacklist_confidence40_ipv4.txt) |

**Verwendungszweck:** Hochkonfidente Bedrohungs-IPs blockieren — bekannte Angreifer, Scanner, Brute-Force-Bots und bösartige Akteure. Empfohlen für **hartes Blockieren**.

---

### Watchlist — Niedrige Konfidenz (20–39%)

| Eigenschaft | Wert |
|---|---|
| **Inhalt** | Verdächtige IPs mit Konfidenzniveau 20–39% |
| **Format** | Eine IP pro Zeile |
| **Update** | Automatisch · Täglich |
| **Raw Link** | [watchlist_confidence20to39_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/watchlist_confidence20to39_ipv4.txt) |

**Verwendungszweck:** Niedrigkonfidente verdächtige IPs überwachen oder weich blockieren — nützlich für Rate-Limiting, Logging oder strengere Inspektionsregeln.

> ⚠️ **Warnung:** Diese Liste hat eine **hohe Falsch-Positiv-Rate**. Viele IPs können legitime Nutzer, Shared-Hosting oder dynamische IPs sein, die vorübergehend markiert wurden. Empfohlen nur für **Logging und Monitoring** — nicht für hartes Blockieren.

---

### 🤖 Bot-Detector-Blacklist

| Eigenschaft | Wert |
|---|---|
| **Inhalt** | Bots, Scraper, Scanner, DDoS-Quellen, VPN/Proxy-Missbrauch, Cloud-Bots |
| **Format** | Eine IP pro Zeile |
| **Update** | Automatisch · Alle 3 Stunden |
| **Raw Link** | [bot_detector_blacklist_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/bot_detector_blacklist_ipv4.txt) |

**Kategorien:**
- KI-Crawler, SEO-Bots, Scraper, Suchmaschinen-Bots
- Schwachstellen-Scanner, Aggressive Scanner
- DDoS-Quellen, Proxy/VPN-Missbrauch
- Hosting/Cloud-Bots (AWS, Azure, DigitalOcean usw.)

**Verwendungszweck:** Bekannte Bots und automatisierte Bedrohungen blockieren — ideal für Webserver, APIs und Dienste, die nur von echten Nutzern erreichbar sein sollen.

> ⚠️ **Hinweis:** Diese Liste enthält Cloud/Hosting-IPs (AWS, Azure, GCP, DigitalOcean usw.). Diese IPs sind als Bots markiert, können aber auch von legitimen Cloud-Nutzern verwendet werden. Empfohlen für **Webserver und APIs** — nicht für allgemeines LAN-Blocking.

---

### 💀 Combined Threat Blacklist

| Eigenschaft | Wert |
|---|---|
| **Inhalt** | Aggregierte Bedrohungs-IPs aus über 20 Threat-Intelligence-Quellen |
| **Format** | Eine IP pro Zeile |
| **Update** | Automatisch · Alle 6 Stunden |
| **Besonderheit** | Liste wächst kontinuierlich — IPs werden nur hinzugefügt, nie entfernt |
| **Raw Link** | [combined_threat_blacklist_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/combined_threat_blacklist_ipv4.txt) |

**Inhalt:**
- Bestätigte Angreifer, Brute-Force-Quellen, SSH-Scanner
- DDoS-Quellen, Botnet-IPs
- Honeypot-Treffer
- Malware-Command-and-Control-Server
- Bekannte bösartige Rechenzentrum-IPs

**Verwendungszweck:** Die umfassendste Blockliste in NETSHIELD — aggregiert aus dutzenden Threat-Intelligence-Feeds und wächst mit jeder Aktualisierung. Ideal für **hartes Blockieren** auf Firewall-Ebene.

---

## ✅ Getestet & Verifiziert

Alle IP-Ranges wurden auf Vorhandensein in `all_countries_ipv4.txt` geprüft:

| Land | Beispiel-IP | Verifiziertes CIDR |
|---|---|---|
| 🇷🇺 Russland | 5.8.18.100 | ✅ 5.8.16.0/21 |
| 🇨🇳 China | 113.195.145.80 | ✅ 113.194.0.0/15 |
| 🇧🇷 Brasilien | 177.75.40.100 | ✅ 177.75.40.0/21 |
| 🇮🇳 Indien | 103.10.197.50 | ✅ 103.10.197.0/24 |
| 🇧🇬 Bulgarien | 31.170.100.50 | ✅ 31.170.100.0/22 |
| 🇻🇳 Vietnam | 45.125.65.50 | ✅ 45.125.64.0/22 |
| 🇷🇴 Rumänien | 82.80.100.200 | ✅ 82.80.0.0/15 |
| 🇵🇰 Pakistan | 203.78.120.30 | ✅ 203.78.112.0/20 |

---

## 🗺️ Hinweise zur Kontinentzuordnung

| Land | Zugeordnet zu | Hinweis |
|---|---|---|
| 🇹🇷 Türkei (TR) | Asien | Transkontinental — Großteil der Landfläche liegt in Asien |
| 🇷🇺 Russland (RU) | Europa | Politisch europäisch, erstreckt sich aber über ganz Asien |
| 🇬🇱 Grönland (GL) | Europa | Dänisches Territorium — geografisch Nordamerika |
| 🇨🇾 Zypern (CY) | Europa | Politisch europäisch (EU-Mitglied), geografisch näher an Asien |

> Für Firewall-Zwecke spielt dies keine Rolle — jede IP ist immer in `all_countries_ipv4.txt` enthalten.

---

## 🔧 Funktioniert gut in Kombination mit

- 🖥️ Rechenzentrum-IP-Listen — AWS, Azure, Hetzner usw.
- 🔒 VPN-Anbieter-Listen — NordVPN, ProtonVPN usw.
- 🧅 TOR-Exit-Node-Listen
- 🕵️ Threat-Intelligence-Feeds
- 🛑 Bekannte bösartige IP-Listen

---

## 📜 Lizenz

Kostenlos für jeden Zweck nutzbar. Keine Namensnennung erforderlich.
