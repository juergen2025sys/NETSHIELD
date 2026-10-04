# Honigtopf – Report
**Aktualisiert:** 2026-10-04 08:24 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 08:24 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,801** |
| Bad Hosts – SIP | **190** |
| Bad Hosts – MSSQL | **482** |
| Bad Hosts – SSH | **3,737** |
| Bad Hosts – SNMP | **440** |
| Bad Hosts – RDP | **710** |
| Bad Hosts – HTTP | **3,036** |
| Bad Hosts – VNC | **261** |
| Bad Hosts – MySQL | **620** |
| Bad Hosts – ProConOs | **168** |
| Bad Hosts – Telnet | **2,733** |
| Bad Hosts – TFTP | **191** |
| Bad Hosts – Redis | **417** |
| Bad Hosts – CouchDB | **389** |
| Bad Hosts – PostgreSQL | **419** |
| Bad Hosts – Kubernetes | **680** |
| Bad Hosts – FTP | **461** |
| Bad Hosts – Elasticsearch | **634** |
| Bad Hosts – ClickhouseHTTP | **317** |
| Bad Hosts – Oracle | **335** |
| Bad Hosts – Memcached | **210** |
| Bad Hosts – Modbus | **167** |
| Bad Hosts – LDAP | **181** |
| Bad Hosts – MQTT | **213** |
| Bad Hosts – RAW | **126** |
| Bad Hosts – IPP | **98** |
| Bad Hosts – LPD | **71** |
| Bad Hosts – HashCountRandom | **63** |
| Bad Hosts – MOTD | **70** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **3,801** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **3,801** |
| 2026-10-03 | **7,000** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,576** |
| Kandidaten dieses Abrufs | **13,576** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+876** |
| Entfernt | **-866** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 08:24 CEST (Berlin)*