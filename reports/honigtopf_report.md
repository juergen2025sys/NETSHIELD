# Honigtopf – Report
**Aktualisiert:** 2026-10-02 11:03 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 11:03 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,589** |
| Bad Hosts – SIP | **171** |
| Bad Hosts – SSH | **3,022** |
| Bad Hosts – MSSQL | **529** |
| Bad Hosts – SNMP | **394** |
| Bad Hosts – RDP | **732** |
| Bad Hosts – HTTP | **3,431** |
| Bad Hosts – VNC | **454** |
| Bad Hosts – MySQL | **647** |
| Bad Hosts – ProConOs | **175** |
| Bad Hosts – Telnet | **3,020** |
| Bad Hosts – FTP | **536** |
| Bad Hosts – TFTP | **189** |
| Bad Hosts – Kubernetes | **789** |
| Bad Hosts – PostgreSQL | **394** |
| Bad Hosts – Redis | **400** |
| Bad Hosts – CouchDB | **309** |
| Bad Hosts – Elasticsearch | **484** |
| Bad Hosts – Oracle | **294** |
| Bad Hosts – ClickhouseHTTP | **264** |
| Bad Hosts – Modbus | **176** |
| Bad Hosts – MQTT | **229** |
| Bad Hosts – Memcached | **230** |
| Bad Hosts – LDAP | **196** |
| Bad Hosts – RAW | **96** |
| Bad Hosts – HashCountRandom | **148** |
| Bad Hosts – IPP | **91** |
| Bad Hosts – LPD | **66** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **4,978** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **4,978** |
| 2026-10-01 | **5,611** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,372** |
| Kandidaten dieses Abrufs | **13,372** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+223** |
| Entfernt | **-147** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 11:03 CEST (Berlin)*