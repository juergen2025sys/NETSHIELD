


<div align="center">

# 🛡️ NETSHIELD

### Vollständige IPv4-Blocklist-Suite für Firewalls & Netzwerksicherheit

![IPv4](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/combined_threat_blacklist_report.md&label=Combined+IPs&query=$.count&color=blue&style=flat-square)
![Länder](https://img.shields.io/badge/L%C3%A4nder-249-green?style=flat-square)
![Kontinente](https://img.shields.io/badge/Kontinente-6-orange?style=flat-square)
![Quellen](https://img.shields.io/badge/Threat--Quellen-31-red?style=flat-square)
![Update](https://img.shields.io/badge/Update-Automatisch-brightgreen?style=flat-square)
![Lizenz](https://img.shields.io/badge/Lizenz-Kostenlos-lightgrey?style=flat-square)

*Entwickelt für OPNsense · pfSense · FortiGate · und jede Firewall mit IP-Blocklist-Unterstützung*

</div>

---

## 📌 Übersicht

NETSHIELD bietet fertige IPv4-Blocklisten, organisiert nach Land, Kontinent und Bedrohungsstufe. Alle Listen werden vollautomatisch über GitHub Actions aktualisiert und sind als Raw-Links verfügbar — einfach in die Firewall einfügen und vergessen.

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

Einzelne Länder blockieren — nach Kontinent organisiert.

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

### 🤖 Bot-Detector-Blacklist

| Eigenschaft | Wert |
|---|---|
| **Inhalt** | Bots, Scraper, Scanner, DDoS-Quellen, VPN/Proxy-Missbrauch, Cloud-Bots |
| **Format** | Eine IP pro Zeile |
| **Update** | Automatisch · Alle 3 Stunden |
| **Raw Link** | [bot_detector_blacklist_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/bot_detector_blacklist_ipv4.txt) |

**Kategorien:** KI-Crawler · SEO-Bots · Scraper · Schwachstellen-Scanner · DDoS-Quellen · Proxy/VPN-Missbrauch · Hosting/Cloud-Bots (AWS, Azure, DigitalOcean usw.)

> ⚠️ **Hinweis:** Enthält Cloud/Hosting-IPs — empfohlen für **Webserver und APIs**, nicht für allgemeines LAN-Blocking.

---

### 💀 Combined Threat Blacklist

| Eigenschaft | Wert |
|---|---|
| **Inhalt** | Kreuzvalidierte Bedrohungs-IPs aus **31 Threat-Intelligence-Quellen** |
| **Format** | Eine IP pro Zeile · sortiert |
| **Update** | Automatisch · Alle 6 Stunden |
| **Raw Link** | [combined_threat_blacklist_ipv4.txt](https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/combined_threat_blacklist_ipv4.txt) |

**Inhalt:** Bestätigte Angreifer · Brute-Force-Quellen · SSH-Scanner · DDoS-Quellen · Botnet-IPs · Honeypot-Treffer · Malware-C2-Server

#### 🔍 Kreuzvalidierungs-Filter

Jede IP wird gegen alle 31 Quellen geprüft. In die finale Liste kommt eine IP nur wenn sie mindestens **eine** dieser Bedingungen erfüllt:

| Bedingung | Bedeutung |
|---|---|
| **2+ Feeds** | IP taucht in mindestens 2 verschiedenen Quellen auf → kreuzvalidiert |
| **1 hochwertiger Feed** | IP steht in einer besonders zuverlässigen Quelle (Feodo, ThreatFox, ThreatView, DShield, Firehol, Binary Defense usw.) |

Dadurch werden Falsch-Positive aus kleineren oder unzuverlässigen Quellen automatisch herausgefiltert.

#### 📡 Feed-Quellen (31 gesamt)

| Kategorie | Quellen |
|---|---|
| **C2 / Malware / IOC** | Feodo Tracker · ThreatFox · ThreatView · trcert-malware · Firehol Cybercrime |
| **Scanner / Brute-Force** | CrowdSec SSH · DShield · CINS Score · Danger Bruteforce · Greensnow · Interserver |
| **DDoS** | L7 DDoS Signatures · Binary Defense |
| **Anonymisierung** | Firehol Anonymous · Cloudzy |
| **Threat-Aggregatoren** | Data-Shield · romainmarcoux (3×) · black-mirror · 4IP Solutions · cyna · bbcan177 · kevinmarx · honeypot-blocklist · nixbear · ufukart · f3csystems · FortiGate Azure · florent banned · edanwong |

#### 🔒 Eingebaute Schutzfilter

Folgende IPs können **nie** in die Liste aufgenommen werden:

- **Bekannte DNS-Server:** Google (8.8.8.8), Cloudflare (1.1.1.1), OpenDNS, Quad9, AdGuard und weitere
- **Private IP-Ranges:** `10.x.x.x` · `172.16–31.x.x` · `192.168.x.x` · `127.x.x.x`
- **Reservierte Ranges:** Multicast (`224+`) · Broadcast · Loopback

---

## ⚙️ Update-Politik

| Liste | Intervall | Methode |
|---|---|---|
| Alle Länder | Mo + Mi 03:00 UTC | GitHub Actions |
| Kontinent-Listen | Bei Bedarf | GitHub Actions |
| Länder-Listen (249) | Bei Bedarf | GitHub Actions |
| Blacklist/Watchlist | Täglich | GitHub Actions |
| Bot-Detector-Blacklist | Alle 3 Stunden | GitHub Actions |
| Combined Threat Blacklist | Alle 6 Stunden | GitHub Actions |

---

## ✅ Getestet & Verifiziert

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
