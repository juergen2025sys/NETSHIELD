# Honigtopf – Report
**Aktualisiert:** 2026-10-04 22:28 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 22:28 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,365** |
| Bad Hosts – SIP | **170** |
| Bad Hosts – SSH | **3,931** |
| Bad Hosts – SNMP | **405** |
| Bad Hosts – MSSQL | **430** |
| Bad Hosts – RDP | **695** |
| Bad Hosts – HTTP | **2,542** |
| Bad Hosts – VNC | **336** |
| Bad Hosts – Telnet | **2,689** |
| Bad Hosts – ProConOs | **144** |
| Bad Hosts – MySQL | **465** |
| Bad Hosts – TFTP | **193** |
| Bad Hosts – Redis | **422** |
| Bad Hosts – FTP | **365** |
| Bad Hosts – PostgreSQL | **559** |
| Bad Hosts – Kubernetes | **688** |
| Bad Hosts – CouchDB | **344** |
| Bad Hosts – Elasticsearch | **527** |
| Bad Hosts – ClickhouseHTTP | **357** |
| Bad Hosts – Oracle | **286** |
| Bad Hosts – Memcached | **222** |
| Bad Hosts – Modbus | **203** |
| Bad Hosts – LDAP | **178** |
| Bad Hosts – MQTT | **215** |
| Bad Hosts – IPP | **108** |
| Bad Hosts – RAW | **119** |
| Bad Hosts – LPD | **84** |
| Bad Hosts – MOTD | **63** |
| Bad Hosts – HashCountRandom | **35** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **9,180** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **9,180** |
| 2026-10-03 | **1,185** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **12,997** |
| Kandidaten dieses Abrufs | **12,997** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+115** |
| Entfernt | **-112** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 22:28 CEST (Berlin)*