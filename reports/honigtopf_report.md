# Honigtopf – Report
**Aktualisiert:** 2026-09-15 21:10 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ✅ gültig (HTTP 200) |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-15 21:10 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **48,263** |
| Bad Hosts – SIP | **203** |
| Bad Hosts – RDP | **1,089** |
| Bad Hosts – SSH | **3,924** |
| Bad Hosts – MSSQL | **602** |
| Bad Hosts – VNC | **1,678** |
| Bad Hosts – HTTP | **4,942** |
| Bad Hosts – FTP | **34,419** |
| Bad Hosts – SNMP | **512** |
| Bad Hosts – TFTP | **232** |
| Bad Hosts – ProConOs | **232** |
| Bad Hosts – Telnet | **3,381** |
| Bad Hosts – MySQL | **779** |
| Bad Hosts – PostgreSQL | **596** |
| Bad Hosts – Kubernetes | **751** |
| Bad Hosts – Redis | **440** |
| Bad Hosts – CouchDB | **271** |
| Bad Hosts – Elasticsearch | **535** |
| Bad Hosts – ClickhouseHTTP | **346** |
| Bad Hosts – Oracle | **319** |
| Bad Hosts – Modbus | **215** |
| Bad Hosts – Memcached | **228** |
| Bad Hosts – LDAP | **231** |
| Bad Hosts – MQTT | **270** |
| Bad Hosts – HashCountRandom | **236** |
| Bad Hosts – RAW | **194** |
| Bad Hosts – IPP | **156** |
| Bad Hosts – LPD | **82** |
| Bad Hosts – MOTD | **69** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-15)**: **40,302** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-15 | **40,302** |
| 2026-09-14 | **7,961** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **51,903** |
| Kandidaten dieses Abrufs | **51,903** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+3,418** |
| Entfernt | **-5,688** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-15 21:10 CEST (Berlin)*