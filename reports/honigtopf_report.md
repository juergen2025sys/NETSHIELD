# Honigtopf – Report
**Aktualisiert:** 2026-10-03 07:10 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-03 07:10 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,429** |
| Bad Hosts – SIP | **153** |
| Bad Hosts – VNC | **380** |
| Bad Hosts – SSH | **2,891** |
| Bad Hosts – SNMP | **393** |
| Bad Hosts – MSSQL | **536** |
| Bad Hosts – RDP | **816** |
| Bad Hosts – HTTP | **4,332** |
| Bad Hosts – MySQL | **618** |
| Bad Hosts – Telnet | **3,040** |
| Bad Hosts – ProConOs | **175** |
| Bad Hosts – TFTP | **186** |
| Bad Hosts – FTP | **516** |
| Bad Hosts – PostgreSQL | **512** |
| Bad Hosts – CouchDB | **283** |
| Bad Hosts – Kubernetes | **747** |
| Bad Hosts – Redis | **496** |
| Bad Hosts – Elasticsearch | **531** |
| Bad Hosts – ClickhouseHTTP | **334** |
| Bad Hosts – Oracle | **278** |
| Bad Hosts – Modbus | **207** |
| Bad Hosts – LDAP | **262** |
| Bad Hosts – RAW | **129** |
| Bad Hosts – Memcached | **205** |
| Bad Hosts – MQTT | **187** |
| Bad Hosts – IPP | **102** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – HashCountRandom | **93** |
| Bad Hosts – MOTD | **34** |
| Bad Hosts – Echo | **6** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-03)**: **3,048** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-03 | **3,048** |
| 2026-10-02 | **8,381** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,428** |
| Kandidaten dieses Abrufs | **14,428** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,609** |
| Entfernt | **-1,875** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-03 07:10 CEST (Berlin)*