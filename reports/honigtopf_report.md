# Honigtopf – Report
**Aktualisiert:** 2026-10-05 16:51 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 16:51 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,158** |
| Bad Hosts – SIP | **185** |
| Bad Hosts – SSH | **4,064** |
| Bad Hosts – MSSQL | **478** |
| Bad Hosts – RDP | **784** |
| Bad Hosts – SNMP | **413** |
| Bad Hosts – HTTP | **3,040** |
| Bad Hosts – Telnet | **2,660** |
| Bad Hosts – MySQL | **515** |
| Bad Hosts – VNC | **348** |
| Bad Hosts – ProConOs | **123** |
| Bad Hosts – TFTP | **192** |
| Bad Hosts – Redis | **392** |
| Bad Hosts – FTP | **478** |
| Bad Hosts – Kubernetes | **754** |
| Bad Hosts – PostgreSQL | **494** |
| Bad Hosts – Elasticsearch | **638** |
| Bad Hosts – ClickhouseHTTP | **381** |
| Bad Hosts – Memcached | **213** |
| Bad Hosts – CouchDB | **375** |
| Bad Hosts – LDAP | **191** |
| Bad Hosts – Oracle | **275** |
| Bad Hosts – Modbus | **188** |
| Bad Hosts – MQTT | **212** |
| Bad Hosts – RAW | **94** |
| Bad Hosts – IPP | **94** |
| Bad Hosts – HashCountRandom | **61** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – MOTD | **64** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **8,108** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **8,108** |
| 2026-10-04 | **3,050** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,789** |
| Kandidaten dieses Abrufs | **13,789** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+10** |
| Entfernt | **-0** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 16:51 CEST (Berlin)*