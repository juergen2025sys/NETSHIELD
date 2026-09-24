# Honigtopf – Report
**Aktualisiert:** 2026-09-24 18:36 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-24 18:36 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,527** |
| Bad Hosts – SIP | **168** |
| Bad Hosts – RDP | **1,030** |
| Bad Hosts – SSH | **3,840** |
| Bad Hosts – MSSQL | **561** |
| Bad Hosts – VNC | **536** |
| Bad Hosts – HTTP | **3,321** |
| Bad Hosts – SNMP | **371** |
| Bad Hosts – TFTP | **174** |
| Bad Hosts – ProConOs | **208** |
| Bad Hosts – Telnet | **3,042** |
| Bad Hosts – MySQL | **668** |
| Bad Hosts – PostgreSQL | **410** |
| Bad Hosts – Elasticsearch | **567** |
| Bad Hosts – FTP | **608** |
| Bad Hosts – Kubernetes | **1,023** |
| Bad Hosts – CouchDB | **1,053** |
| Bad Hosts – Redis | **439** |
| Bad Hosts – ClickhouseHTTP | **352** |
| Bad Hosts – RAW | **258** |
| Bad Hosts – Oracle | **265** |
| Bad Hosts – Memcached | **326** |
| Bad Hosts – Modbus | **250** |
| Bad Hosts – LDAP | **248** |
| Bad Hosts – MQTT | **262** |
| Bad Hosts – IPP | **130** |
| Bad Hosts – LPD | **62** |
| Bad Hosts – MOTD | **80** |
| Bad Hosts – HashCountRandom | **46** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-24)**: **9,082** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-24 | **9,082** |
| 2026-09-23 | **3,445** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,396** |
| Kandidaten dieses Abrufs | **15,396** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+761** |
| Entfernt | **-2,043** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-24 18:36 CEST (Berlin)*