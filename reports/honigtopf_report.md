# Honigtopf – Report
**Aktualisiert:** 2026-09-26 14:29 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-26 14:29 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,656** |
| Bad Hosts – SIP | **161** |
| Bad Hosts – SSH | **3,089** |
| Bad Hosts – RDP | **961** |
| Bad Hosts – MSSQL | **464** |
| Bad Hosts – HTTP | **2,962** |
| Bad Hosts – SNMP | **383** |
| Bad Hosts – TFTP | **187** |
| Bad Hosts – VNC | **410** |
| Bad Hosts – ProConOs | **219** |
| Bad Hosts – Telnet | **3,058** |
| Bad Hosts – PostgreSQL | **592** |
| Bad Hosts – MySQL | **608** |
| Bad Hosts – FTP | **550** |
| Bad Hosts – Kubernetes | **741** |
| Bad Hosts – Redis | **461** |
| Bad Hosts – Elasticsearch | **540** |
| Bad Hosts – ClickhouseHTTP | **256** |
| Bad Hosts – CouchDB | **216** |
| Bad Hosts – Oracle | **333** |
| Bad Hosts – Modbus | **207** |
| Bad Hosts – Memcached | **206** |
| Bad Hosts – RAW | **166** |
| Bad Hosts – MQTT | **237** |
| Bad Hosts – IPP | **104** |
| Bad Hosts – LDAP | **211** |
| Bad Hosts – LPD | **72** |
| Bad Hosts – HashCountRandom | **38** |
| Bad Hosts – MOTD | **50** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **6,349** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **6,349** |
| 2026-09-25 | **4,307** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,386** |
| Kandidaten dieses Abrufs | **13,386** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+331** |
| Entfernt | **-776** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-26 14:29 CEST (Berlin)*