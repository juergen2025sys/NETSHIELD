# Honigtopf – Report
**Aktualisiert:** 2026-10-03 16:57 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ unklar (410) – im Pool belassen |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-03 16:57 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,332** |
| Bad Hosts – SIP | **165** |
| Bad Hosts – SSH | **3,104** |
| Bad Hosts – MSSQL | **514** |
| Bad Hosts – RDP | **747** |
| Bad Hosts – SNMP | **378** |
| Bad Hosts – VNC | **278** |
| Bad Hosts – HTTP | **4,032** |
| Bad Hosts – MySQL | **617** |
| Bad Hosts – Telnet | **2,960** |
| Bad Hosts – ProConOs | **116** |
| Bad Hosts – TFTP | **203** |
| Bad Hosts – CouchDB | **369** |
| Bad Hosts – Redis | **494** |
| Bad Hosts – Kubernetes | **703** |
| Bad Hosts – PostgreSQL | **489** |
| Bad Hosts – Elasticsearch | **643** |
| Bad Hosts – FTP | **490** |
| Bad Hosts – Oracle | **280** |
| Bad Hosts – ClickhouseHTTP | **324** |
| Bad Hosts – Modbus | **177** |
| Bad Hosts – Memcached | **213** |
| Bad Hosts – RAW | **123** |
| Bad Hosts – LDAP | **225** |
| Bad Hosts – MQTT | **178** |
| Bad Hosts – IPP | **102** |
| Bad Hosts – HashCountRandom | **85** |
| Bad Hosts – LPD | **54** |
| Bad Hosts – MOTD | **60** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-03)**: **7,422** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-03 | **7,422** |
| 2026-10-02 | **3,910** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,252** |
| Kandidaten dieses Abrufs | **14,252** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+659** |
| Entfernt | **-732** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-03 16:57 CEST (Berlin)*