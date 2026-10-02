# Honigtopf – Report
**Aktualisiert:** 2026-10-02 07:30 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 07:30 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,446** |
| Bad Hosts – SIP | **155** |
| Bad Hosts – SSH | **2,940** |
| Bad Hosts – MSSQL | **504** |
| Bad Hosts – RDP | **748** |
| Bad Hosts – SNMP | **405** |
| Bad Hosts – HTTP | **3,297** |
| Bad Hosts – MySQL | **728** |
| Bad Hosts – VNC | **363** |
| Bad Hosts – ProConOs | **148** |
| Bad Hosts – Telnet | **2,981** |
| Bad Hosts – FTP | **558** |
| Bad Hosts – TFTP | **198** |
| Bad Hosts – PostgreSQL | **392** |
| Bad Hosts – Kubernetes | **719** |
| Bad Hosts – Redis | **398** |
| Bad Hosts – Elasticsearch | **519** |
| Bad Hosts – CouchDB | **327** |
| Bad Hosts – Oracle | **244** |
| Bad Hosts – Modbus | **199** |
| Bad Hosts – ClickhouseHTTP | **236** |
| Bad Hosts – Memcached | **229** |
| Bad Hosts – MQTT | **233** |
| Bad Hosts – LDAP | **173** |
| Bad Hosts – IPP | **99** |
| Bad Hosts – HashCountRandom | **149** |
| Bad Hosts – RAW | **89** |
| Bad Hosts – LPD | **72** |
| Bad Hosts – MOTD | **62** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **3,158** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **3,158** |
| 2026-10-01 | **7,288** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,212** |
| Kandidaten dieses Abrufs | **13,212** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,227** |
| Entfernt | **-950** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 07:30 CEST (Berlin)*