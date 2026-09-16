# Honigtopf – Report
**Aktualisiert:** 2026-09-16 22:05 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ✅ gültig (HTTP 200) |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 22:05 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **45,288** |
| Bad Hosts – SIP | **228** |
| Bad Hosts – MSSQL | **613** |
| Bad Hosts – SSH | **3,550** |
| Bad Hosts – RDP | **1,268** |
| Bad Hosts – VNC | **1,578** |
| Bad Hosts – HTTP | **4,532** |
| Bad Hosts – FTP | **32,137** |
| Bad Hosts – TFTP | **306** |
| Bad Hosts – SNMP | **506** |
| Bad Hosts – Telnet | **3,349** |
| Bad Hosts – ProConOs | **138** |
| Bad Hosts – MySQL | **634** |
| Bad Hosts – CouchDB | **235** |
| Bad Hosts – PostgreSQL | **628** |
| Bad Hosts – Kubernetes | **988** |
| Bad Hosts – Redis | **437** |
| Bad Hosts – Elasticsearch | **540** |
| Bad Hosts – Oracle | **264** |
| Bad Hosts – ClickhouseHTTP | **293** |
| Bad Hosts – Modbus | **233** |
| Bad Hosts – Memcached | **224** |
| Bad Hosts – LDAP | **251** |
| Bad Hosts – RAW | **225** |
| Bad Hosts – IPP | **135** |
| Bad Hosts – MQTT | **210** |
| Bad Hosts – HashCountRandom | **204** |
| Bad Hosts – LPD | **101** |
| Bad Hosts – MOTD | **53** |
| Bad Hosts – WebLogic | **3** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-16)**: **39,546** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-16 | **39,546** |
| 2026-09-15 | **5,742** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **49,301** |
| Kandidaten dieses Abrufs | **49,301** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,395** |
| Entfernt | **-2,302** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 22:05 CEST (Berlin)*