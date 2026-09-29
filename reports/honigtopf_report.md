# Honigtopf – Report
**Aktualisiert:** 2026-09-29 10:40 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 10:40 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,403** |
| Bad Hosts – SIP | **161** |
| Bad Hosts – MSSQL | **493** |
| Bad Hosts – SSH | **2,790** |
| Bad Hosts – RDP | **732** |
| Bad Hosts – SNMP | **298** |
| Bad Hosts – HTTP | **4,702** |
| Bad Hosts – VNC | **295** |
| Bad Hosts – ProConOs | **143** |
| Bad Hosts – Telnet | **2,509** |
| Bad Hosts – PostgreSQL | **436** |
| Bad Hosts – TFTP | **193** |
| Bad Hosts – MySQL | **377** |
| Bad Hosts – Kubernetes | **685** |
| Bad Hosts – Elasticsearch | **571** |
| Bad Hosts – FTP | **326** |
| Bad Hosts – Redis | **332** |
| Bad Hosts – CouchDB | **271** |
| Bad Hosts – ClickhouseHTTP | **278** |
| Bad Hosts – LDAP | **184** |
| Bad Hosts – Oracle | **235** |
| Bad Hosts – RAW | **144** |
| Bad Hosts – Modbus | **173** |
| Bad Hosts – MQTT | **171** |
| Bad Hosts – Memcached | **188** |
| Bad Hosts – IPP | **105** |
| Bad Hosts – HashCountRandom | **72** |
| Bad Hosts – LPD | **45** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-29)**: **6,963** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-29 | **6,963** |
| 2026-09-28 | **4,440** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,689** |
| Kandidaten dieses Abrufs | **13,689** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+134** |
| Entfernt | **-81** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 10:40 CEST (Berlin)*