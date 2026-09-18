# Honigtopf – Report
**Aktualisiert:** 2026-09-19 01:50 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-19 01:50 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **38,559** |
| Bad Hosts – SIP | **182** |
| Bad Hosts – MSSQL | **903** |
| Bad Hosts – SSH | **3,869** |
| Bad Hosts – VNC | **1,594** |
| Bad Hosts – RDP | **1,065** |
| Bad Hosts – SNMP | **456** |
| Bad Hosts – HTTP | **4,797** |
| Bad Hosts – TFTP | **226** |
| Bad Hosts – FTP | **25,396** |
| Bad Hosts – Telnet | **2,929** |
| Bad Hosts – ProConOs | **160** |
| Bad Hosts – PostgreSQL | **561** |
| Bad Hosts – MySQL | **528** |
| Bad Hosts – Kubernetes | **735** |
| Bad Hosts – Redis | **450** |
| Bad Hosts – Elasticsearch | **423** |
| Bad Hosts – CouchDB | **239** |
| Bad Hosts – ClickhouseHTTP | **265** |
| Bad Hosts – Modbus | **211** |
| Bad Hosts – Oracle | **264** |
| Bad Hosts – RAW | **260** |
| Bad Hosts – LDAP | **253** |
| Bad Hosts – LPD | **101** |
| Bad Hosts – Memcached | **220** |
| Bad Hosts – MQTT | **211** |
| Bad Hosts – IPP | **123** |
| Bad Hosts – HashCountRandom | **142** |
| Bad Hosts – MOTD | **54** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **38,279** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-19 | **73** |
| 2026-09-18 | **38,279** |
| 2026-09-17 | **207** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **41,951** |
| Kandidaten dieses Abrufs | **41,951** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+454** |
| Entfernt | **-656** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-19 01:50 CEST (Berlin)*