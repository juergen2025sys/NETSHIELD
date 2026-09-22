# Honigtopf – Report
**Aktualisiert:** 2026-09-23 00:06 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 00:06 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,175** |
| Bad Hosts – SIP | **270** |
| Bad Hosts – RDP | **953** |
| Bad Hosts – MSSQL | **546** |
| Bad Hosts – SSH | **3,930** |
| Bad Hosts – SNMP | **403** |
| Bad Hosts – HTTP | **2,915** |
| Bad Hosts – VNC | **344** |
| Bad Hosts – Telnet | **2,821** |
| Bad Hosts – TFTP | **209** |
| Bad Hosts – MySQL | **666** |
| Bad Hosts – ProConOs | **149** |
| Bad Hosts – PostgreSQL | **602** |
| Bad Hosts – FTP | **543** |
| Bad Hosts – Kubernetes | **739** |
| Bad Hosts – Redis | **420** |
| Bad Hosts – Elasticsearch | **569** |
| Bad Hosts – CouchDB | **236** |
| Bad Hosts – ClickhouseHTTP | **269** |
| Bad Hosts – MQTT | **245** |
| Bad Hosts – Oracle | **292** |
| Bad Hosts – Modbus | **226** |
| Bad Hosts – LDAP | **301** |
| Bad Hosts – RAW | **236** |
| Bad Hosts – Memcached | **262** |
| Bad Hosts – IPP | **128** |
| Bad Hosts – LPD | **103** |
| Bad Hosts – HashCountRandom | **106** |
| Bad Hosts – MOTD | **64** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-22)**: **10,550** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-22 | **10,550** |
| 2026-09-21 | **625** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,131** |
| Kandidaten dieses Abrufs | **14,131** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+197** |
| Entfernt | **-219** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 00:06 CEST (Berlin)*