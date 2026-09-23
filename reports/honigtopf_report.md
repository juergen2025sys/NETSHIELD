# Honigtopf – Report
**Aktualisiert:** 2026-09-23 17:10 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 17:10 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,487** |
| Bad Hosts – SIP | **171** |
| Bad Hosts – RDP | **1,046** |
| Bad Hosts – SSH | **3,988** |
| Bad Hosts – MSSQL | **655** |
| Bad Hosts – SNMP | **402** |
| Bad Hosts – HTTP | **2,890** |
| Bad Hosts – VNC | **406** |
| Bad Hosts – TFTP | **194** |
| Bad Hosts – Telnet | **2,774** |
| Bad Hosts – MySQL | **700** |
| Bad Hosts – ProConOs | **177** |
| Bad Hosts – FTP | **601** |
| Bad Hosts – PostgreSQL | **513** |
| Bad Hosts – Kubernetes | **792** |
| Bad Hosts – Redis | **504** |
| Bad Hosts – Elasticsearch | **625** |
| Bad Hosts – CouchDB | **342** |
| Bad Hosts – Oracle | **337** |
| Bad Hosts – ClickhouseHTTP | **239** |
| Bad Hosts – Modbus | **269** |
| Bad Hosts – Memcached | **289** |
| Bad Hosts – RAW | **233** |
| Bad Hosts – LDAP | **312** |
| Bad Hosts – MQTT | **227** |
| Bad Hosts – IPP | **103** |
| Bad Hosts – HashCountRandom | **88** |
| Bad Hosts – LPD | **95** |
| Bad Hosts – MOTD | **55** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-23)**: **8,291** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **8,291** |
| 2026-09-22 | **3,196** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,483** |
| Kandidaten dieses Abrufs | **14,483** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+361** |
| Entfernt | **-324** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 17:10 CEST (Berlin)*