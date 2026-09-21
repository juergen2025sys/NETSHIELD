# Honigtopf – Report
**Aktualisiert:** 2026-09-21 07:08 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-21 07:08 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,045** |
| Bad Hosts – RDP | **1,062** |
| Bad Hosts – SSH | **4,518** |
| Bad Hosts – SIP | **196** |
| Bad Hosts – MSSQL | **580** |
| Bad Hosts – SNMP | **391** |
| Bad Hosts – HTTP | **2,341** |
| Bad Hosts – VNC | **1,367** |
| Bad Hosts – Telnet | **2,964** |
| Bad Hosts – ProConOs | **145** |
| Bad Hosts – TFTP | **266** |
| Bad Hosts – PostgreSQL | **533** |
| Bad Hosts – MySQL | **420** |
| Bad Hosts – FTP | **357** |
| Bad Hosts – Kubernetes | **678** |
| Bad Hosts – Redis | **304** |
| Bad Hosts – Elasticsearch | **336** |
| Bad Hosts – CouchDB | **187** |
| Bad Hosts – ClickhouseHTTP | **209** |
| Bad Hosts – Oracle | **278** |
| Bad Hosts – Memcached | **172** |
| Bad Hosts – RAW | **203** |
| Bad Hosts – LDAP | **226** |
| Bad Hosts – Modbus | **151** |
| Bad Hosts – MQTT | **196** |
| Bad Hosts – IPP | **101** |
| Bad Hosts – LPD | **73** |
| Bad Hosts – HashCountRandom | **39** |
| Bad Hosts – MOTD | **55** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-21)**: **3,172** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-21 | **3,172** |
| 2026-09-20 | **8,873** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,612** |
| Kandidaten dieses Abrufs | **14,612** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,533** |
| Entfernt | **-3,750** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-21 07:08 CEST (Berlin)*