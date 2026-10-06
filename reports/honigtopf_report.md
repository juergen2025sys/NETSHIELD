# Honigtopf – Report
**Aktualisiert:** 2026-10-06 16:29 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 16:29 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,391** |
| Bad Hosts – SIP | **173** |
| Bad Hosts – SSH | **3,717** |
| Bad Hosts – SNMP | **411** |
| Bad Hosts – MSSQL | **497** |
| Bad Hosts – RDP | **838** |
| Bad Hosts – TFTP | **217** |
| Bad Hosts – VNC | **342** |
| Bad Hosts – HTTP | **3,613** |
| Bad Hosts – Telnet | **2,619** |
| Bad Hosts – MySQL | **688** |
| Bad Hosts – FTP | **560** |
| Bad Hosts – Memcached | **228** |
| Bad Hosts – ProConOs | **165** |
| Bad Hosts – Kubernetes | **906** |
| Bad Hosts – Redis | **446** |
| Bad Hosts – PostgreSQL | **547** |
| Bad Hosts – CouchDB | **375** |
| Bad Hosts – ClickhouseHTTP | **335** |
| Bad Hosts – Elasticsearch | **678** |
| Bad Hosts – Oracle | **266** |
| Bad Hosts – Modbus | **194** |
| Bad Hosts – LDAP | **257** |
| Bad Hosts – MQTT | **256** |
| Bad Hosts – RAW | **143** |
| Bad Hosts – HashCountRandom | **109** |
| Bad Hosts – LPD | **95** |
| Bad Hosts – IPP | **118** |
| Bad Hosts – MOTD | **76** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **7,832** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **7,832** |
| 2026-10-05 | **3,559** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,095** |
| Kandidaten dieses Abrufs | **14,095** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+136** |
| Entfernt | **-126** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 16:29 CEST (Berlin)*