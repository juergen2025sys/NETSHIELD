# Honigtopf – Report
**Aktualisiert:** 2026-10-03 20:39 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-03 20:39 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,226** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – MSSQL | **503** |
| Bad Hosts – SSH | **3,270** |
| Bad Hosts – RDP | **746** |
| Bad Hosts – SNMP | **373** |
| Bad Hosts – VNC | **262** |
| Bad Hosts – HTTP | **4,004** |
| Bad Hosts – MySQL | **607** |
| Bad Hosts – Telnet | **2,839** |
| Bad Hosts – ProConOs | **122** |
| Bad Hosts – TFTP | **194** |
| Bad Hosts – Redis | **448** |
| Bad Hosts – PostgreSQL | **442** |
| Bad Hosts – CouchDB | **371** |
| Bad Hosts – Kubernetes | **643** |
| Bad Hosts – Elasticsearch | **630** |
| Bad Hosts – FTP | **492** |
| Bad Hosts – Oracle | **273** |
| Bad Hosts – ClickhouseHTTP | **318** |
| Bad Hosts – Memcached | **231** |
| Bad Hosts – Modbus | **173** |
| Bad Hosts – LDAP | **220** |
| Bad Hosts – RAW | **125** |
| Bad Hosts – MQTT | **168** |
| Bad Hosts – IPP | **91** |
| Bad Hosts – HashCountRandom | **89** |
| Bad Hosts – LPD | **55** |
| Bad Hosts – MOTD | **61** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-03)**: **8,828** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-03 | **8,828** |
| 2026-10-02 | **2,398** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,132** |
| Kandidaten dieses Abrufs | **14,132** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+482** |
| Entfernt | **-403** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-03 20:39 CEST (Berlin)*