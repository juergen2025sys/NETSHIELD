# Honigtopf – Report
**Aktualisiert:** 2026-10-02 22:11 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 22:11 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,626** |
| Bad Hosts – SIP | **158** |
| Bad Hosts – SSH | **2,946** |
| Bad Hosts – VNC | **438** |
| Bad Hosts – SNMP | **367** |
| Bad Hosts – MSSQL | **514** |
| Bad Hosts – HTTP | **4,246** |
| Bad Hosts – RDP | **807** |
| Bad Hosts – MySQL | **608** |
| Bad Hosts – Telnet | **3,000** |
| Bad Hosts – ProConOs | **189** |
| Bad Hosts – FTP | **540** |
| Bad Hosts – TFTP | **196** |
| Bad Hosts – PostgreSQL | **445** |
| Bad Hosts – Kubernetes | **820** |
| Bad Hosts – CouchDB | **330** |
| Bad Hosts – Redis | **424** |
| Bad Hosts – Elasticsearch | **476** |
| Bad Hosts – ClickhouseHTTP | **337** |
| Bad Hosts – Oracle | **276** |
| Bad Hosts – Modbus | **193** |
| Bad Hosts – MQTT | **219** |
| Bad Hosts – Memcached | **257** |
| Bad Hosts – LDAP | **190** |
| Bad Hosts – RAW | **123** |
| Bad Hosts – IPP | **117** |
| Bad Hosts – HashCountRandom | **126** |
| Bad Hosts – LPD | **75** |
| Bad Hosts – MOTD | **36** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **9,368** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **9,368** |
| 2026-10-01 | **1,258** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,269** |
| Kandidaten dieses Abrufs | **14,269** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+888** |
| Entfernt | **-83** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 22:11 CEST (Berlin)*