# Honigtopf – Report
**Aktualisiert:** 2026-09-28 10:21 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-28 10:21 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **9,425** |
| Bad Hosts – SIP | **138** |
| Bad Hosts – SSH | **3,312** |
| Bad Hosts – RDP | **765** |
| Bad Hosts – MSSQL | **476** |
| Bad Hosts – SNMP | **294** |
| Bad Hosts – VNC | **346** |
| Bad Hosts – HTTP | **1,893** |
| Bad Hosts – PostgreSQL | **382** |
| Bad Hosts – TFTP | **140** |
| Bad Hosts – Telnet | **2,722** |
| Bad Hosts – ProConOs | **130** |
| Bad Hosts – FTP | **237** |
| Bad Hosts – MySQL | **300** |
| Bad Hosts – Kubernetes | **724** |
| Bad Hosts – Elasticsearch | **524** |
| Bad Hosts – CouchDB | **230** |
| Bad Hosts – Redis | **356** |
| Bad Hosts – Oracle | **188** |
| Bad Hosts – ClickhouseHTTP | **250** |
| Bad Hosts – Modbus | **146** |
| Bad Hosts – IPP | **95** |
| Bad Hosts – LDAP | **226** |
| Bad Hosts – RAW | **134** |
| Bad Hosts – MQTT | **183** |
| Bad Hosts – Memcached | **182** |
| Bad Hosts – HashCountRandom | **26** |
| Bad Hosts – LPD | **51** |
| Bad Hosts – MOTD | **26** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-28)**: **3,470** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-28 | **3,470** |
| 2026-09-27 | **5,955** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **11,485** |
| Kandidaten dieses Abrufs | **11,485** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+163** |
| Entfernt | **-231** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-28 10:21 CEST (Berlin)*