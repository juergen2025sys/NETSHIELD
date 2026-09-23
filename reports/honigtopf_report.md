# Honigtopf – Report
**Aktualisiert:** 2026-09-23 12:15 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 12:15 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,327** |
| Bad Hosts – RDP | **992** |
| Bad Hosts – SIP | **212** |
| Bad Hosts – SSH | **3,958** |
| Bad Hosts – MSSQL | **606** |
| Bad Hosts – SNMP | **391** |
| Bad Hosts – HTTP | **2,813** |
| Bad Hosts – VNC | **433** |
| Bad Hosts – TFTP | **201** |
| Bad Hosts – Telnet | **2,806** |
| Bad Hosts – MySQL | **762** |
| Bad Hosts – ProConOs | **159** |
| Bad Hosts – FTP | **617** |
| Bad Hosts – PostgreSQL | **506** |
| Bad Hosts – Kubernetes | **699** |
| Bad Hosts – Redis | **471** |
| Bad Hosts – CouchDB | **299** |
| Bad Hosts – Elasticsearch | **604** |
| Bad Hosts – ClickhouseHTTP | **239** |
| Bad Hosts – Oracle | **299** |
| Bad Hosts – RAW | **280** |
| Bad Hosts – LDAP | **317** |
| Bad Hosts – Modbus | **215** |
| Bad Hosts – Memcached | **246** |
| Bad Hosts – MQTT | **221** |
| Bad Hosts – IPP | **127** |
| Bad Hosts – HashCountRandom | **68** |
| Bad Hosts – LPD | **97** |
| Bad Hosts – MOTD | **64** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-23)**: **5,987** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **5,987** |
| 2026-09-22 | **5,340** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,271** |
| Kandidaten dieses Abrufs | **14,271** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+255** |
| Entfernt | **-273** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 12:15 CEST (Berlin)*