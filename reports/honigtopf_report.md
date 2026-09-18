# Honigtopf – Report
**Aktualisiert:** 2026-09-18 23:50 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 23:50 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **38,440** |
| Bad Hosts – SIP | **189** |
| Bad Hosts – MSSQL | **916** |
| Bad Hosts – SSH | **3,831** |
| Bad Hosts – VNC | **1,596** |
| Bad Hosts – RDP | **1,047** |
| Bad Hosts – SNMP | **447** |
| Bad Hosts – HTTP | **4,521** |
| Bad Hosts – TFTP | **244** |
| Bad Hosts – FTP | **25,541** |
| Bad Hosts – Telnet | **2,933** |
| Bad Hosts – ProConOs | **162** |
| Bad Hosts – PostgreSQL | **556** |
| Bad Hosts – MySQL | **529** |
| Bad Hosts – Kubernetes | **705** |
| Bad Hosts – Redis | **457** |
| Bad Hosts – Elasticsearch | **420** |
| Bad Hosts – CouchDB | **268** |
| Bad Hosts – ClickhouseHTTP | **256** |
| Bad Hosts – Oracle | **246** |
| Bad Hosts – RAW | **261** |
| Bad Hosts – Modbus | **170** |
| Bad Hosts – LDAP | **245** |
| Bad Hosts – MQTT | **219** |
| Bad Hosts – Memcached | **220** |
| Bad Hosts – IPP | **120** |
| Bad Hosts – HashCountRandom | **194** |
| Bad Hosts – LPD | **89** |
| Bad Hosts – MOTD | **54** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **36,281** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **36,281** |
| 2026-09-17 | **2,159** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **41,811** |
| Kandidaten dieses Abrufs | **41,811** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+691** |
| Entfernt | **-1,038** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 23:50 CEST (Berlin)*