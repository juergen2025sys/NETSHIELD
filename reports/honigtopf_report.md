# Honigtopf – Report
**Aktualisiert:** 2026-09-18 20:36 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 20:36 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **39,073** |
| Bad Hosts – SIP | **181** |
| Bad Hosts – MSSQL | **918** |
| Bad Hosts – VNC | **1,633** |
| Bad Hosts – SSH | **3,853** |
| Bad Hosts – RDP | **1,070** |
| Bad Hosts – SNMP | **435** |
| Bad Hosts – HTTP | **4,490** |
| Bad Hosts – TFTP | **245** |
| Bad Hosts – FTP | **25,989** |
| Bad Hosts – Telnet | **2,947** |
| Bad Hosts – PostgreSQL | **540** |
| Bad Hosts – ProConOs | **164** |
| Bad Hosts – MySQL | **642** |
| Bad Hosts – Kubernetes | **707** |
| Bad Hosts – Redis | **447** |
| Bad Hosts – Elasticsearch | **415** |
| Bad Hosts – CouchDB | **240** |
| Bad Hosts – ClickhouseHTTP | **268** |
| Bad Hosts – Oracle | **276** |
| Bad Hosts – Modbus | **171** |
| Bad Hosts – RAW | **267** |
| Bad Hosts – LDAP | **229** |
| Bad Hosts – MQTT | **236** |
| Bad Hosts – Memcached | **232** |
| Bad Hosts – HashCountRandom | **195** |
| Bad Hosts – IPP | **97** |
| Bad Hosts – LPD | **78** |
| Bad Hosts – MOTD | **54** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **31,232** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **31,232** |
| 2026-09-17 | **7,841** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **42,437** |
| Kandidaten dieses Abrufs | **42,437** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,456** |
| Entfernt | **-1,497** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 20:36 CEST (Berlin)*