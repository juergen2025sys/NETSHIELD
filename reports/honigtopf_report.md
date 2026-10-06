# Honigtopf – Report
**Aktualisiert:** 2026-10-06 02:46 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 02:46 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,389** |
| Bad Hosts – SSH | **3,893** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – SNMP | **460** |
| Bad Hosts – MSSQL | **512** |
| Bad Hosts – RDP | **823** |
| Bad Hosts – HTTP | **3,466** |
| Bad Hosts – MySQL | **588** |
| Bad Hosts – Telnet | **2,649** |
| Bad Hosts – VNC | **341** |
| Bad Hosts – ProConOs | **116** |
| Bad Hosts – Memcached | **176** |
| Bad Hosts – TFTP | **202** |
| Bad Hosts – Kubernetes | **747** |
| Bad Hosts – PostgreSQL | **541** |
| Bad Hosts – Redis | **444** |
| Bad Hosts – FTP | **529** |
| Bad Hosts – Elasticsearch | **687** |
| Bad Hosts – ClickhouseHTTP | **361** |
| Bad Hosts – CouchDB | **356** |
| Bad Hosts – LDAP | **242** |
| Bad Hosts – Oracle | **283** |
| Bad Hosts – Modbus | **209** |
| Bad Hosts – MQTT | **232** |
| Bad Hosts – RAW | **120** |
| Bad Hosts – IPP | **95** |
| Bad Hosts – HashCountRandom | **87** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – MOTD | **73** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **857** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **857** |
| 2026-10-05 | **10,532** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,109** |
| Kandidaten dieses Abrufs | **14,109** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+882** |
| Entfernt | **-1,057** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 02:46 CEST (Berlin)*