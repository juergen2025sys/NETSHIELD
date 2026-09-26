# Honigtopf – Report
**Aktualisiert:** 2026-09-26 23:33 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-26 23:33 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,638** |
| Bad Hosts – SIP | **169** |
| Bad Hosts – SSH | **3,049** |
| Bad Hosts – RDP | **1,024** |
| Bad Hosts – MSSQL | **451** |
| Bad Hosts – SNMP | **355** |
| Bad Hosts – HTTP | **3,073** |
| Bad Hosts – TFTP | **176** |
| Bad Hosts – PostgreSQL | **605** |
| Bad Hosts – ProConOs | **201** |
| Bad Hosts – Telnet | **3,001** |
| Bad Hosts – MySQL | **668** |
| Bad Hosts – VNC | **397** |
| Bad Hosts – Kubernetes | **740** |
| Bad Hosts – FTP | **515** |
| Bad Hosts – Redis | **439** |
| Bad Hosts – Elasticsearch | **501** |
| Bad Hosts – Oracle | **290** |
| Bad Hosts – CouchDB | **224** |
| Bad Hosts – ClickhouseHTTP | **228** |
| Bad Hosts – RAW | **184** |
| Bad Hosts – Memcached | **240** |
| Bad Hosts – Modbus | **215** |
| Bad Hosts – MQTT | **226** |
| Bad Hosts – IPP | **135** |
| Bad Hosts – LDAP | **220** |
| Bad Hosts – MOTD | **83** |
| Bad Hosts – HashCountRandom | **57** |
| Bad Hosts – LPD | **67** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **9,938** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **9,938** |
| 2026-09-25 | **700** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,320** |
| Kandidaten dieses Abrufs | **13,320** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+219** |
| Entfernt | **-247** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-26 23:33 CEST (Berlin)*