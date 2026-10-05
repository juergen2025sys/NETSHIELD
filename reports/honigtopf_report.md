# Honigtopf – Report
**Aktualisiert:** 2026-10-05 15:11 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 15:11 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,137** |
| Bad Hosts – SIP | **185** |
| Bad Hosts – SSH | **4,134** |
| Bad Hosts – RDP | **719** |
| Bad Hosts – MSSQL | **485** |
| Bad Hosts – SNMP | **406** |
| Bad Hosts – HTTP | **2,994** |
| Bad Hosts – Telnet | **2,674** |
| Bad Hosts – MySQL | **488** |
| Bad Hosts – ProConOs | **137** |
| Bad Hosts – VNC | **371** |
| Bad Hosts – TFTP | **191** |
| Bad Hosts – Redis | **387** |
| Bad Hosts – FTP | **454** |
| Bad Hosts – Kubernetes | **748** |
| Bad Hosts – PostgreSQL | **530** |
| Bad Hosts – ClickhouseHTTP | **379** |
| Bad Hosts – CouchDB | **374** |
| Bad Hosts – Elasticsearch | **632** |
| Bad Hosts – Memcached | **231** |
| Bad Hosts – LDAP | **188** |
| Bad Hosts – Oracle | **274** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – IPP | **103** |
| Bad Hosts – MQTT | **191** |
| Bad Hosts – RAW | **116** |
| Bad Hosts – LPD | **79** |
| Bad Hosts – HashCountRandom | **49** |
| Bad Hosts – MOTD | **45** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **7,373** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **7,373** |
| 2026-10-04 | **3,764** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,792** |
| Kandidaten dieses Abrufs | **13,792** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,537** |
| Entfernt | **-1,151** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 15:11 CEST (Berlin)*