# Honigtopf – Report
**Aktualisiert:** 2026-10-04 01:07 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 01:07 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,650** |
| Bad Hosts – SIP | **177** |
| Bad Hosts – MSSQL | **491** |
| Bad Hosts – SSH | **3,527** |
| Bad Hosts – RDP | **769** |
| Bad Hosts – SNMP | **391** |
| Bad Hosts – VNC | **249** |
| Bad Hosts – HTTP | **3,255** |
| Bad Hosts – MySQL | **694** |
| Bad Hosts – Telnet | **2,783** |
| Bad Hosts – ProConOs | **132** |
| Bad Hosts – TFTP | **188** |
| Bad Hosts – Redis | **443** |
| Bad Hosts – CouchDB | **387** |
| Bad Hosts – PostgreSQL | **470** |
| Bad Hosts – Kubernetes | **656** |
| Bad Hosts – Elasticsearch | **664** |
| Bad Hosts – FTP | **496** |
| Bad Hosts – Oracle | **284** |
| Bad Hosts – ClickhouseHTTP | **298** |
| Bad Hosts – Memcached | **205** |
| Bad Hosts – Modbus | **184** |
| Bad Hosts – LDAP | **212** |
| Bad Hosts – RAW | **127** |
| Bad Hosts – MQTT | **188** |
| Bad Hosts – IPP | **76** |
| Bad Hosts – HashCountRandom | **84** |
| Bad Hosts – MOTD | **64** |
| Bad Hosts – LPD | **49** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-03)**: **10,378** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **4** |
| 2026-10-03 | **10,378** |
| 2026-10-02 | **268** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,561** |
| Kandidaten dieses Abrufs | **13,561** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+712** |
| Entfernt | **-1,472** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 01:07 CEST (Berlin)*