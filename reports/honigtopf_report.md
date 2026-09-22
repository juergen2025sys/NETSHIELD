# Honigtopf – Report
**Aktualisiert:** 2026-09-23 01:52 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 01:52 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,248** |
| Bad Hosts – SIP | **271** |
| Bad Hosts – RDP | **949** |
| Bad Hosts – SSH | **4,006** |
| Bad Hosts – MSSQL | **536** |
| Bad Hosts – SNMP | **390** |
| Bad Hosts – HTTP | **2,886** |
| Bad Hosts – VNC | **355** |
| Bad Hosts – Telnet | **2,828** |
| Bad Hosts – TFTP | **212** |
| Bad Hosts – MySQL | **669** |
| Bad Hosts – ProConOs | **148** |
| Bad Hosts – PostgreSQL | **589** |
| Bad Hosts – FTP | **541** |
| Bad Hosts – Kubernetes | **725** |
| Bad Hosts – Redis | **442** |
| Bad Hosts – Elasticsearch | **579** |
| Bad Hosts – CouchDB | **247** |
| Bad Hosts – ClickhouseHTTP | **273** |
| Bad Hosts – MQTT | **249** |
| Bad Hosts – Oracle | **300** |
| Bad Hosts – LDAP | **337** |
| Bad Hosts – Modbus | **218** |
| Bad Hosts – RAW | **252** |
| Bad Hosts – Memcached | **271** |
| Bad Hosts – IPP | **131** |
| Bad Hosts – LPD | **101** |
| Bad Hosts – HashCountRandom | **105** |
| Bad Hosts – MOTD | **65** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-22)**: **11,157** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **21** |
| 2026-09-22 | **11,157** |
| 2026-09-21 | **70** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,228** |
| Kandidaten dieses Abrufs | **14,228** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+151** |
| Entfernt | **-195** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 01:52 CEST (Berlin)*