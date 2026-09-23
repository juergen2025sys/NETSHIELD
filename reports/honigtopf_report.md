# Honigtopf – Report
**Aktualisiert:** 2026-09-23 21:05 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ✅ gültig (HTTP 200) |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 21:05 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,594** |
| Bad Hosts – SIP | **148** |
| Bad Hosts – RDP | **1,118** |
| Bad Hosts – SSH | **4,046** |
| Bad Hosts – MSSQL | **625** |
| Bad Hosts – HTTP | **3,086** |
| Bad Hosts – SNMP | **401** |
| Bad Hosts – VNC | **380** |
| Bad Hosts – TFTP | **183** |
| Bad Hosts – Telnet | **2,836** |
| Bad Hosts – ProConOs | **224** |
| Bad Hosts – MySQL | **676** |
| Bad Hosts – FTP | **584** |
| Bad Hosts – PostgreSQL | **495** |
| Bad Hosts – Kubernetes | **803** |
| Bad Hosts – Redis | **494** |
| Bad Hosts – CouchDB | **353** |
| Bad Hosts – Elasticsearch | **610** |
| Bad Hosts – Oracle | **312** |
| Bad Hosts – ClickhouseHTTP | **231** |
| Bad Hosts – Modbus | **255** |
| Bad Hosts – Memcached | **262** |
| Bad Hosts – LDAP | **309** |
| Bad Hosts – RAW | **226** |
| Bad Hosts – MQTT | **237** |
| Bad Hosts – IPP | **96** |
| Bad Hosts – HashCountRandom | **80** |
| Bad Hosts – LPD | **83** |
| Bad Hosts – MOTD | **65** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-23)**: **9,998** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **9,998** |
| 2026-09-22 | **1,596** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,464** |
| Kandidaten dieses Abrufs | **14,464** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+142** |
| Entfernt | **-163** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 21:05 CEST (Berlin)*