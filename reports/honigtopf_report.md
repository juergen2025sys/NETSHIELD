# Honigtopf – Report
**Aktualisiert:** 2026-10-05 11:33 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 11:33 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,864** |
| Bad Hosts – SIP | **175** |
| Bad Hosts – SSH | **4,124** |
| Bad Hosts – RDP | **727** |
| Bad Hosts – MSSQL | **484** |
| Bad Hosts – SNMP | **386** |
| Bad Hosts – HTTP | **2,774** |
| Bad Hosts – Telnet | **2,769** |
| Bad Hosts – MySQL | **477** |
| Bad Hosts – VNC | **320** |
| Bad Hosts – ProConOs | **127** |
| Bad Hosts – TFTP | **198** |
| Bad Hosts – FTP | **409** |
| Bad Hosts – Redis | **398** |
| Bad Hosts – Kubernetes | **746** |
| Bad Hosts – PostgreSQL | **540** |
| Bad Hosts – CouchDB | **374** |
| Bad Hosts – Elasticsearch | **583** |
| Bad Hosts – ClickhouseHTTP | **351** |
| Bad Hosts – LDAP | **199** |
| Bad Hosts – Oracle | **282** |
| Bad Hosts – Memcached | **227** |
| Bad Hosts – Modbus | **219** |
| Bad Hosts – MQTT | **196** |
| Bad Hosts – RAW | **112** |
| Bad Hosts – IPP | **87** |
| Bad Hosts – HashCountRandom | **44** |
| Bad Hosts – LPD | **74** |
| Bad Hosts – MOTD | **61** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **5,834** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **5,834** |
| 2026-10-04 | **5,030** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,400** |
| Kandidaten dieses Abrufs | **13,400** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+860** |
| Entfernt | **-1,376** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 11:33 CEST (Berlin)*