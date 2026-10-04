# Honigtopf – Report
**Aktualisiert:** 2026-10-04 14:46 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 14:46 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,523** |
| Bad Hosts – SIP | **181** |
| Bad Hosts – SSH | **3,869** |
| Bad Hosts – MSSQL | **442** |
| Bad Hosts – SNMP | **412** |
| Bad Hosts – RDP | **713** |
| Bad Hosts – HTTP | **2,837** |
| Bad Hosts – VNC | **283** |
| Bad Hosts – Telnet | **2,706** |
| Bad Hosts – ProConOs | **142** |
| Bad Hosts – MySQL | **541** |
| Bad Hosts – TFTP | **179** |
| Bad Hosts – Redis | **428** |
| Bad Hosts – FTP | **412** |
| Bad Hosts – PostgreSQL | **450** |
| Bad Hosts – CouchDB | **330** |
| Bad Hosts – Kubernetes | **676** |
| Bad Hosts – Elasticsearch | **538** |
| Bad Hosts – ClickhouseHTTP | **374** |
| Bad Hosts – Oracle | **302** |
| Bad Hosts – Memcached | **224** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – MQTT | **231** |
| Bad Hosts – LDAP | **175** |
| Bad Hosts – IPP | **79** |
| Bad Hosts – RAW | **112** |
| Bad Hosts – LPD | **64** |
| Bad Hosts – HashCountRandom | **50** |
| Bad Hosts – MOTD | **74** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **6,479** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **6,479** |
| 2026-10-03 | **4,044** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,182** |
| Kandidaten dieses Abrufs | **13,182** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+796** |
| Entfernt | **-836** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 14:46 CEST (Berlin)*