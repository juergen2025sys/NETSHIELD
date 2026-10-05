# Honigtopf – Report
**Aktualisiert:** 2026-10-05 18:33 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 18:33 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,215** |
| Bad Hosts – SSH | **4,001** |
| Bad Hosts – SIP | **175** |
| Bad Hosts – SNMP | **420** |
| Bad Hosts – MSSQL | **475** |
| Bad Hosts – RDP | **824** |
| Bad Hosts – HTTP | **3,200** |
| Bad Hosts – MySQL | **573** |
| Bad Hosts – Telnet | **2,657** |
| Bad Hosts – VNC | **350** |
| Bad Hosts – ProConOs | **126** |
| Bad Hosts – TFTP | **186** |
| Bad Hosts – FTP | **477** |
| Bad Hosts – Redis | **392** |
| Bad Hosts – Kubernetes | **743** |
| Bad Hosts – PostgreSQL | **502** |
| Bad Hosts – Memcached | **212** |
| Bad Hosts – Elasticsearch | **658** |
| Bad Hosts – ClickhouseHTTP | **370** |
| Bad Hosts – CouchDB | **390** |
| Bad Hosts – LDAP | **193** |
| Bad Hosts – Oracle | **280** |
| Bad Hosts – Modbus | **190** |
| Bad Hosts – MQTT | **207** |
| Bad Hosts – RAW | **103** |
| Bad Hosts – IPP | **98** |
| Bad Hosts – HashCountRandom | **63** |
| Bad Hosts – LPD | **62** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **8,784** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **8,784** |
| 2026-10-04 | **2,431** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,908** |
| Kandidaten dieses Abrufs | **13,908** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+24** |
| Entfernt | **-84** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 18:33 CEST (Berlin)*