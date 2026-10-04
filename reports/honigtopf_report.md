# Honigtopf – Report
**Aktualisiert:** 2026-10-04 23:54 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 23:54 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,318** |
| Bad Hosts – SIP | **168** |
| Bad Hosts – SSH | **3,906** |
| Bad Hosts – SNMP | **398** |
| Bad Hosts – MSSQL | **447** |
| Bad Hosts – RDP | **682** |
| Bad Hosts – HTTP | **2,539** |
| Bad Hosts – VNC | **333** |
| Bad Hosts – Telnet | **2,690** |
| Bad Hosts – ProConOs | **145** |
| Bad Hosts – TFTP | **192** |
| Bad Hosts – MySQL | **411** |
| Bad Hosts – FTP | **359** |
| Bad Hosts – Redis | **412** |
| Bad Hosts – PostgreSQL | **558** |
| Bad Hosts – Kubernetes | **697** |
| Bad Hosts – CouchDB | **360** |
| Bad Hosts – ClickhouseHTTP | **354** |
| Bad Hosts – Elasticsearch | **523** |
| Bad Hosts – Oracle | **286** |
| Bad Hosts – Memcached | **218** |
| Bad Hosts – Modbus | **219** |
| Bad Hosts – LDAP | **198** |
| Bad Hosts – MQTT | **213** |
| Bad Hosts – IPP | **110** |
| Bad Hosts – RAW | **117** |
| Bad Hosts – LPD | **84** |
| Bad Hosts – MOTD | **63** |
| Bad Hosts – HashCountRandom | **33** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **9,651** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **9,651** |
| 2026-10-03 | **667** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **12,904** |
| Kandidaten dieses Abrufs | **12,904** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+502** |
| Entfernt | **-595** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 23:54 CEST (Berlin)*