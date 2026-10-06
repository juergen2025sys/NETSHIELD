# Honigtopf – Report
**Aktualisiert:** 2026-10-06 17:05 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 17:05 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,396** |
| Bad Hosts – SIP | **171** |
| Bad Hosts – SSH | **3,719** |
| Bad Hosts – SNMP | **411** |
| Bad Hosts – MSSQL | **493** |
| Bad Hosts – RDP | **814** |
| Bad Hosts – TFTP | **216** |
| Bad Hosts – VNC | **343** |
| Bad Hosts – HTTP | **3,588** |
| Bad Hosts – Telnet | **2,633** |
| Bad Hosts – MySQL | **664** |
| Bad Hosts – FTP | **549** |
| Bad Hosts – Memcached | **226** |
| Bad Hosts – ProConOs | **167** |
| Bad Hosts – Kubernetes | **903** |
| Bad Hosts – Redis | **444** |
| Bad Hosts – PostgreSQL | **546** |
| Bad Hosts – CouchDB | **394** |
| Bad Hosts – ClickhouseHTTP | **341** |
| Bad Hosts – Elasticsearch | **658** |
| Bad Hosts – Oracle | **262** |
| Bad Hosts – Modbus | **216** |
| Bad Hosts – LDAP | **261** |
| Bad Hosts – MQTT | **255** |
| Bad Hosts – RAW | **141** |
| Bad Hosts – HashCountRandom | **109** |
| Bad Hosts – LPD | **95** |
| Bad Hosts – IPP | **118** |
| Bad Hosts – MOTD | **78** |
| Bad Hosts – BitcoinRPC | **1** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – Docker | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **8,174** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **8,174** |
| 2026-10-05 | **3,222** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,999** |
| Kandidaten dieses Abrufs | **13,999** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+280** |
| Entfernt | **-376** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 17:05 CEST (Berlin)*