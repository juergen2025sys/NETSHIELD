# Honigtopf – Report
**Aktualisiert:** 2026-10-02 16:12 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 16:12 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,658** |
| Bad Hosts – SIP | **168** |
| Bad Hosts – SSH | **2,983** |
| Bad Hosts – SNMP | **389** |
| Bad Hosts – MSSQL | **526** |
| Bad Hosts – VNC | **458** |
| Bad Hosts – HTTP | **3,544** |
| Bad Hosts – RDP | **774** |
| Bad Hosts – MySQL | **624** |
| Bad Hosts – ProConOs | **214** |
| Bad Hosts – Telnet | **3,028** |
| Bad Hosts – FTP | **571** |
| Bad Hosts – TFTP | **196** |
| Bad Hosts – PostgreSQL | **400** |
| Bad Hosts – Kubernetes | **859** |
| Bad Hosts – CouchDB | **312** |
| Bad Hosts – Redis | **405** |
| Bad Hosts – Elasticsearch | **507** |
| Bad Hosts – ClickhouseHTTP | **265** |
| Bad Hosts – Oracle | **257** |
| Bad Hosts – Modbus | **220** |
| Bad Hosts – MQTT | **234** |
| Bad Hosts – Memcached | **226** |
| Bad Hosts – LDAP | **188** |
| Bad Hosts – RAW | **104** |
| Bad Hosts – HashCountRandom | **159** |
| Bad Hosts – IPP | **94** |
| Bad Hosts – LPD | **81** |
| Bad Hosts – MOTD | **41** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **6,946** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **6,946** |
| 2026-10-01 | **3,712** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,542** |
| Kandidaten dieses Abrufs | **13,542** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+297** |
| Entfernt | **-1,118** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 16:12 CEST (Berlin)*