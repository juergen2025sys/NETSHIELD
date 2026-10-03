# Honigtopf – Report
**Aktualisiert:** 2026-10-03 22:10 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-03 22:10 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,984** |
| Bad Hosts – SIP | **184** |
| Bad Hosts – MSSQL | **494** |
| Bad Hosts – SSH | **3,347** |
| Bad Hosts – RDP | **758** |
| Bad Hosts – SNMP | **399** |
| Bad Hosts – VNC | **242** |
| Bad Hosts – HTTP | **3,308** |
| Bad Hosts – MySQL | **619** |
| Bad Hosts – Telnet | **2,849** |
| Bad Hosts – ProConOs | **133** |
| Bad Hosts – TFTP | **195** |
| Bad Hosts – Redis | **439** |
| Bad Hosts – CouchDB | **374** |
| Bad Hosts – PostgreSQL | **436** |
| Bad Hosts – Kubernetes | **639** |
| Bad Hosts – Elasticsearch | **642** |
| Bad Hosts – FTP | **476** |
| Bad Hosts – Oracle | **274** |
| Bad Hosts – ClickhouseHTTP | **287** |
| Bad Hosts – Memcached | **215** |
| Bad Hosts – Modbus | **173** |
| Bad Hosts – LDAP | **226** |
| Bad Hosts – RAW | **123** |
| Bad Hosts – MQTT | **174** |
| Bad Hosts – IPP | **83** |
| Bad Hosts – HashCountRandom | **91** |
| Bad Hosts – LPD | **53** |
| Bad Hosts – MOTD | **63** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-03)**: **9,423** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-03 | **9,423** |
| 2026-10-02 | **1,561** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,890** |
| Kandidaten dieses Abrufs | **13,890** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+332** |
| Entfernt | **-890** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-03 22:10 CEST (Berlin)*