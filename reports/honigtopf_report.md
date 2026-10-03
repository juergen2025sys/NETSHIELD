# Honigtopf – Report
**Aktualisiert:** 2026-10-04 01:59 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 01:59 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,674** |
| Bad Hosts – SIP | **181** |
| Bad Hosts – MSSQL | **491** |
| Bad Hosts – SSH | **3,562** |
| Bad Hosts – RDP | **765** |
| Bad Hosts – SNMP | **410** |
| Bad Hosts – VNC | **246** |
| Bad Hosts – HTTP | **3,196** |
| Bad Hosts – MySQL | **670** |
| Bad Hosts – ProConOs | **134** |
| Bad Hosts – Telnet | **2,763** |
| Bad Hosts – TFTP | **195** |
| Bad Hosts – Redis | **439** |
| Bad Hosts – CouchDB | **390** |
| Bad Hosts – PostgreSQL | **442** |
| Bad Hosts – Kubernetes | **663** |
| Bad Hosts – Elasticsearch | **671** |
| Bad Hosts – FTP | **494** |
| Bad Hosts – Oracle | **290** |
| Bad Hosts – ClickhouseHTTP | **301** |
| Bad Hosts – Memcached | **210** |
| Bad Hosts – Modbus | **190** |
| Bad Hosts – LDAP | **210** |
| Bad Hosts – RAW | **128** |
| Bad Hosts – MQTT | **185** |
| Bad Hosts – IPP | **76** |
| Bad Hosts – HashCountRandom | **52** |
| Bad Hosts – MOTD | **65** |
| Bad Hosts – LPD | **47** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-03)**: **10,592** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **15** |
| 2026-10-03 | **10,592** |
| 2026-10-02 | **67** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,530** |
| Kandidaten dieses Abrufs | **13,530** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+301** |
| Entfernt | **-332** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 01:59 CEST (Berlin)*