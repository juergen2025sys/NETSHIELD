# Honigtopf – Report
**Aktualisiert:** 2026-10-03 01:31 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-03 01:31 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,315** |
| Bad Hosts – SIP | **165** |
| Bad Hosts – SSH | **2,848** |
| Bad Hosts – VNC | **403** |
| Bad Hosts – SNMP | **387** |
| Bad Hosts – MSSQL | **516** |
| Bad Hosts – HTTP | **4,297** |
| Bad Hosts – RDP | **779** |
| Bad Hosts – MySQL | **593** |
| Bad Hosts – Telnet | **3,015** |
| Bad Hosts – ProConOs | **178** |
| Bad Hosts – FTP | **515** |
| Bad Hosts – TFTP | **206** |
| Bad Hosts – PostgreSQL | **476** |
| Bad Hosts – Kubernetes | **774** |
| Bad Hosts – CouchDB | **325** |
| Bad Hosts – Redis | **456** |
| Bad Hosts – Elasticsearch | **493** |
| Bad Hosts – ClickhouseHTTP | **330** |
| Bad Hosts – Oracle | **282** |
| Bad Hosts – Modbus | **196** |
| Bad Hosts – MQTT | **213** |
| Bad Hosts – LDAP | **223** |
| Bad Hosts – RAW | **126** |
| Bad Hosts – Memcached | **238** |
| Bad Hosts – IPP | **127** |
| Bad Hosts – LPD | **71** |
| Bad Hosts – HashCountRandom | **90** |
| Bad Hosts – MOTD | **36** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **11,168** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-03 | **12** |
| 2026-10-02 | **11,168** |
| 2026-10-01 | **135** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,246** |
| Kandidaten dieses Abrufs | **14,246** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+506** |
| Entfernt | **-986** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-03 01:31 CEST (Berlin)*