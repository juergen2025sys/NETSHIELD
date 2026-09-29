# Honigtopf – Report
**Aktualisiert:** 2026-09-29 03:21 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 03:21 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **7,949** |
| Bad Hosts – SIP | **149** |
| Bad Hosts – SSH | **2,639** |
| Bad Hosts – RDP | **619** |
| Bad Hosts – MSSQL | **465** |
| Bad Hosts – VNC | **267** |
| Bad Hosts – SNMP | **253** |
| Bad Hosts – HTTP | **1,930** |
| Bad Hosts – ProConOs | **158** |
| Bad Hosts – Telnet | **2,168** |
| Bad Hosts – TFTP | **146** |
| Bad Hosts – PostgreSQL | **423** |
| Bad Hosts – MySQL | **297** |
| Bad Hosts – Kubernetes | **626** |
| Bad Hosts – Elasticsearch | **496** |
| Bad Hosts – FTP | **217** |
| Bad Hosts – Redis | **277** |
| Bad Hosts – CouchDB | **180** |
| Bad Hosts – LDAP | **169** |
| Bad Hosts – ClickhouseHTTP | **237** |
| Bad Hosts – Oracle | **197** |
| Bad Hosts – MQTT | **196** |
| Bad Hosts – Modbus | **162** |
| Bad Hosts – RAW | **130** |
| Bad Hosts – Memcached | **151** |
| Bad Hosts – HashCountRandom | **63** |
| Bad Hosts – IPP | **106** |
| Bad Hosts – MOTD | **56** |
| Bad Hosts – LPD | **44** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-29)**: **855** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-29 | **855** |
| 2026-09-28 | **7,094** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **10,095** |
| Kandidaten dieses Abrufs | **10,095** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+675** |
| Entfernt | **-1,147** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 03:21 CEST (Berlin)*