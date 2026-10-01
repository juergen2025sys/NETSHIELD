# Honigtopf – Report
**Aktualisiert:** 2026-10-02 01:26 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 01:26 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,417** |
| Bad Hosts – SIP | **167** |
| Bad Hosts – SSH | **3,091** |
| Bad Hosts – RDP | **696** |
| Bad Hosts – MSSQL | **493** |
| Bad Hosts – HTTP | **3,177** |
| Bad Hosts – SNMP | **387** |
| Bad Hosts – VNC | **361** |
| Bad Hosts – MySQL | **664** |
| Bad Hosts – ProConOs | **129** |
| Bad Hosts – Telnet | **3,011** |
| Bad Hosts – FTP | **539** |
| Bad Hosts – TFTP | **192** |
| Bad Hosts – PostgreSQL | **306** |
| Bad Hosts – Kubernetes | **642** |
| Bad Hosts – Redis | **369** |
| Bad Hosts – Elasticsearch | **536** |
| Bad Hosts – CouchDB | **257** |
| Bad Hosts – Oracle | **248** |
| Bad Hosts – ClickhouseHTTP | **232** |
| Bad Hosts – Modbus | **188** |
| Bad Hosts – Memcached | **212** |
| Bad Hosts – MQTT | **196** |
| Bad Hosts – LDAP | **161** |
| Bad Hosts – IPP | **81** |
| Bad Hosts – HashCountRandom | **155** |
| Bad Hosts – RAW | **88** |
| Bad Hosts – LPD | **59** |
| Bad Hosts – MOTD | **70** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-01)**: **10,163** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **5** |
| 2026-10-01 | **10,163** |
| 2026-09-30 | **249** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,053** |
| Kandidaten dieses Abrufs | **13,053** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+82** |
| Entfernt | **-105** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 01:26 CEST (Berlin)*