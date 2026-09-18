# Honigtopf – Report
**Aktualisiert:** 2026-09-19 01:17 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-19 01:17 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **38,551** |
| Bad Hosts – SIP | **185** |
| Bad Hosts – MSSQL | **902** |
| Bad Hosts – SSH | **3,837** |
| Bad Hosts – VNC | **1,592** |
| Bad Hosts – RDP | **1,076** |
| Bad Hosts – SNMP | **455** |
| Bad Hosts – HTTP | **4,807** |
| Bad Hosts – TFTP | **233** |
| Bad Hosts – FTP | **25,421** |
| Bad Hosts – Telnet | **2,929** |
| Bad Hosts – ProConOs | **159** |
| Bad Hosts – PostgreSQL | **546** |
| Bad Hosts – MySQL | **527** |
| Bad Hosts – Kubernetes | **737** |
| Bad Hosts – Redis | **451** |
| Bad Hosts – Elasticsearch | **426** |
| Bad Hosts – CouchDB | **237** |
| Bad Hosts – Modbus | **211** |
| Bad Hosts – ClickhouseHTTP | **264** |
| Bad Hosts – Oracle | **259** |
| Bad Hosts – RAW | **262** |
| Bad Hosts – LDAP | **247** |
| Bad Hosts – LPD | **100** |
| Bad Hosts – MQTT | **209** |
| Bad Hosts – Memcached | **219** |
| Bad Hosts – IPP | **117** |
| Bad Hosts – HashCountRandom | **171** |
| Bad Hosts – MOTD | **54** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **37,720** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-19 | **3** |
| 2026-09-18 | **37,720** |
| 2026-09-17 | **828** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **42,153** |
| Kandidaten dieses Abrufs | **42,153** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,730** |
| Entfernt | **-1,388** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-19 01:17 CEST (Berlin)*