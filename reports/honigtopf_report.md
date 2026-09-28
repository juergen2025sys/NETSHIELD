# Honigtopf – Report
**Aktualisiert:** 2026-09-28 10:37 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-28 10:37 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **9,398** |
| Bad Hosts – SIP | **141** |
| Bad Hosts – SSH | **3,266** |
| Bad Hosts – RDP | **774** |
| Bad Hosts – MSSQL | **475** |
| Bad Hosts – SNMP | **295** |
| Bad Hosts – VNC | **349** |
| Bad Hosts – HTTP | **1,901** |
| Bad Hosts – PostgreSQL | **409** |
| Bad Hosts – TFTP | **138** |
| Bad Hosts – Telnet | **2,745** |
| Bad Hosts – ProConOs | **131** |
| Bad Hosts – FTP | **238** |
| Bad Hosts – MySQL | **298** |
| Bad Hosts – Kubernetes | **713** |
| Bad Hosts – Elasticsearch | **519** |
| Bad Hosts – CouchDB | **232** |
| Bad Hosts – Redis | **357** |
| Bad Hosts – Oracle | **194** |
| Bad Hosts – ClickhouseHTTP | **254** |
| Bad Hosts – Modbus | **146** |
| Bad Hosts – IPP | **95** |
| Bad Hosts – LDAP | **222** |
| Bad Hosts – MQTT | **200** |
| Bad Hosts – RAW | **131** |
| Bad Hosts – HashCountRandom | **26** |
| Bad Hosts – Memcached | **180** |
| Bad Hosts – LPD | **51** |
| Bad Hosts – MOTD | **27** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-28)**: **3,550** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-28 | **3,550** |
| 2026-09-27 | **5,848** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **11,494** |
| Kandidaten dieses Abrufs | **11,494** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+115** |
| Entfernt | **-106** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-28 10:37 CEST (Berlin)*