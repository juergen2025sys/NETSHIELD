# Honigtopf – Report
**Aktualisiert:** 2026-09-20 16:14 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-20 16:14 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **26,358** |
| Bad Hosts – RDP | **960** |
| Bad Hosts – MSSQL | **644** |
| Bad Hosts – SSH | **4,707** |
| Bad Hosts – SIP | **206** |
| Bad Hosts – SNMP | **437** |
| Bad Hosts – VNC | **1,647** |
| Bad Hosts – HTTP | **4,179** |
| Bad Hosts – FTP | **12,099** |
| Bad Hosts – TFTP | **314** |
| Bad Hosts – MySQL | **496** |
| Bad Hosts – Telnet | **2,890** |
| Bad Hosts – ProConOs | **118** |
| Bad Hosts – PostgreSQL | **488** |
| Bad Hosts – Kubernetes | **709** |
| Bad Hosts – Oracle | **303** |
| Bad Hosts – Redis | **340** |
| Bad Hosts – Elasticsearch | **469** |
| Bad Hosts – MQTT | **282** |
| Bad Hosts – CouchDB | **193** |
| Bad Hosts – Memcached | **257** |
| Bad Hosts – ClickhouseHTTP | **222** |
| Bad Hosts – LDAP | **258** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – RAW | **216** |
| Bad Hosts – HashCountRandom | **119** |
| Bad Hosts – IPP | **70** |
| Bad Hosts – LPD | **50** |
| Bad Hosts – MOTD | **39** |
| Bad Hosts – WebLogic | **1** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-20)**: **10,257** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-20 | **10,257** |
| 2026-09-19 | **16,101** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **29,211** |
| Kandidaten dieses Abrufs | **29,211** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+781** |
| Entfernt | **-7,335** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-20 16:14 CEST (Berlin)*