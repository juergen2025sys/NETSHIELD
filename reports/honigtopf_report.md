# Honigtopf – Report
**Aktualisiert:** 2026-10-04 02:32 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 02:32 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,694** |
| Bad Hosts – SIP | **178** |
| Bad Hosts – MSSQL | **488** |
| Bad Hosts – SSH | **3,566** |
| Bad Hosts – RDP | **744** |
| Bad Hosts – SNMP | **410** |
| Bad Hosts – VNC | **247** |
| Bad Hosts – HTTP | **3,191** |
| Bad Hosts – MySQL | **661** |
| Bad Hosts – ProConOs | **137** |
| Bad Hosts – Telnet | **2,776** |
| Bad Hosts – TFTP | **194** |
| Bad Hosts – Redis | **441** |
| Bad Hosts – CouchDB | **391** |
| Bad Hosts – PostgreSQL | **442** |
| Bad Hosts – Elasticsearch | **649** |
| Bad Hosts – Kubernetes | **657** |
| Bad Hosts – FTP | **496** |
| Bad Hosts – Oracle | **293** |
| Bad Hosts – ClickhouseHTTP | **299** |
| Bad Hosts – Memcached | **215** |
| Bad Hosts – Modbus | **192** |
| Bad Hosts – LDAP | **211** |
| Bad Hosts – RAW | **130** |
| Bad Hosts – MQTT | **189** |
| Bad Hosts – IPP | **77** |
| Bad Hosts – HashCountRandom | **55** |
| Bad Hosts – MOTD | **65** |
| Bad Hosts – LPD | **48** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **635** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **635** |
| 2026-10-03 | **10,059** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,448** |
| Kandidaten dieses Abrufs | **13,448** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+201** |
| Entfernt | **-283** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 02:32 CEST (Berlin)*