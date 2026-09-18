# Honigtopf – Report
**Aktualisiert:** 2026-09-18 14:39 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 14:39 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **40,035** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – MSSQL | **928** |
| Bad Hosts – VNC | **1,533** |
| Bad Hosts – SSH | **3,801** |
| Bad Hosts – RDP | **1,150** |
| Bad Hosts – SNMP | **438** |
| Bad Hosts – HTTP | **4,503** |
| Bad Hosts – TFTP | **227** |
| Bad Hosts – FTP | **26,829** |
| Bad Hosts – ProConOs | **176** |
| Bad Hosts – Telnet | **2,998** |
| Bad Hosts – PostgreSQL | **549** |
| Bad Hosts – MySQL | **669** |
| Bad Hosts – Kubernetes | **758** |
| Bad Hosts – Redis | **386** |
| Bad Hosts – Elasticsearch | **428** |
| Bad Hosts – CouchDB | **247** |
| Bad Hosts – Oracle | **287** |
| Bad Hosts – ClickhouseHTTP | **260** |
| Bad Hosts – Modbus | **168** |
| Bad Hosts – LDAP | **245** |
| Bad Hosts – Memcached | **249** |
| Bad Hosts – RAW | **223** |
| Bad Hosts – MQTT | **241** |
| Bad Hosts – IPP | **84** |
| Bad Hosts – HashCountRandom | **183** |
| Bad Hosts – LPD | **62** |
| Bad Hosts – MOTD | **53** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **20,423** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **20,423** |
| 2026-09-17 | **19,612** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **43,381** |
| Kandidaten dieses Abrufs | **43,381** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,804** |
| Entfernt | **-2,106** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 14:39 CEST (Berlin)*