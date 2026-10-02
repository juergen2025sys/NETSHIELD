# Honigtopf – Report
**Aktualisiert:** 2026-10-02 17:45 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 17:45 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,576** |
| Bad Hosts – SIP | **157** |
| Bad Hosts – SSH | **2,987** |
| Bad Hosts – SNMP | **372** |
| Bad Hosts – VNC | **449** |
| Bad Hosts – MSSQL | **531** |
| Bad Hosts – HTTP | **3,479** |
| Bad Hosts – RDP | **800** |
| Bad Hosts – MySQL | **620** |
| Bad Hosts – ProConOs | **209** |
| Bad Hosts – Telnet | **3,051** |
| Bad Hosts – FTP | **572** |
| Bad Hosts – TFTP | **191** |
| Bad Hosts – PostgreSQL | **381** |
| Bad Hosts – Kubernetes | **831** |
| Bad Hosts – CouchDB | **314** |
| Bad Hosts – Redis | **388** |
| Bad Hosts – Elasticsearch | **496** |
| Bad Hosts – ClickhouseHTTP | **274** |
| Bad Hosts – Oracle | **259** |
| Bad Hosts – Modbus | **230** |
| Bad Hosts – MQTT | **228** |
| Bad Hosts – Memcached | **231** |
| Bad Hosts – LDAP | **190** |
| Bad Hosts – RAW | **123** |
| Bad Hosts – IPP | **109** |
| Bad Hosts – LPD | **92** |
| Bad Hosts – HashCountRandom | **130** |
| Bad Hosts – MOTD | **42** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **7,605** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **7,605** |
| 2026-10-01 | **2,971** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,437** |
| Kandidaten dieses Abrufs | **13,437** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+326** |
| Entfernt | **-344** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 17:45 CEST (Berlin)*