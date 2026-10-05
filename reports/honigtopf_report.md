# Honigtopf – Report
**Aktualisiert:** 2026-10-05 02:20 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 02:20 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,418** |
| Bad Hosts – SIP | **176** |
| Bad Hosts – SSH | **3,948** |
| Bad Hosts – SNMP | **372** |
| Bad Hosts – MSSQL | **456** |
| Bad Hosts – RDP | **707** |
| Bad Hosts – HTTP | **2,532** |
| Bad Hosts – Telnet | **2,725** |
| Bad Hosts – VNC | **355** |
| Bad Hosts – ProConOs | **148** |
| Bad Hosts – TFTP | **192** |
| Bad Hosts – FTP | **351** |
| Bad Hosts – MySQL | **409** |
| Bad Hosts – Redis | **397** |
| Bad Hosts – PostgreSQL | **565** |
| Bad Hosts – Kubernetes | **713** |
| Bad Hosts – CouchDB | **345** |
| Bad Hosts – ClickhouseHTTP | **370** |
| Bad Hosts – Elasticsearch | **521** |
| Bad Hosts – Oracle | **289** |
| Bad Hosts – Memcached | **225** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – LDAP | **185** |
| Bad Hosts – MQTT | **209** |
| Bad Hosts – IPP | **108** |
| Bad Hosts – RAW | **104** |
| Bad Hosts – LPD | **82** |
| Bad Hosts – HashCountRandom | **35** |
| Bad Hosts – MOTD | **62** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **463** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **463** |
| 2026-10-04 | **9,955** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **12,995** |
| Kandidaten dieses Abrufs | **12,995** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+375** |
| Entfernt | **-275** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 02:20 CEST (Berlin)*