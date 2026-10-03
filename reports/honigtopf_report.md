# Honigtopf – Report
**Aktualisiert:** 2026-10-03 12:23 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-03 12:23 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,371** |
| Bad Hosts – SIP | **156** |
| Bad Hosts – SSH | **2,845** |
| Bad Hosts – VNC | **292** |
| Bad Hosts – MSSQL | **502** |
| Bad Hosts – SNMP | **375** |
| Bad Hosts – RDP | **816** |
| Bad Hosts – HTTP | **4,242** |
| Bad Hosts – MySQL | **615** |
| Bad Hosts – Telnet | **2,988** |
| Bad Hosts – ProConOs | **160** |
| Bad Hosts – TFTP | **206** |
| Bad Hosts – CouchDB | **375** |
| Bad Hosts – Kubernetes | **720** |
| Bad Hosts – PostgreSQL | **532** |
| Bad Hosts – Redis | **512** |
| Bad Hosts – FTP | **507** |
| Bad Hosts – Elasticsearch | **637** |
| Bad Hosts – Oracle | **277** |
| Bad Hosts – ClickhouseHTTP | **342** |
| Bad Hosts – Modbus | **216** |
| Bad Hosts – Memcached | **220** |
| Bad Hosts – RAW | **136** |
| Bad Hosts – LDAP | **228** |
| Bad Hosts – MQTT | **171** |
| Bad Hosts – IPP | **109** |
| Bad Hosts – LPD | **66** |
| Bad Hosts – HashCountRandom | **107** |
| Bad Hosts – MOTD | **49** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Echo | **6** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-03)**: **5,432** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-03 | **5,432** |
| 2026-10-02 | **5,939** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,366** |
| Kandidaten dieses Abrufs | **14,366** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+917** |
| Entfernt | **-827** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-03 12:23 CEST (Berlin)*