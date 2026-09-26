# Honigtopf – Report
**Aktualisiert:** 2026-09-26 02:25 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-26 02:25 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,000** |
| Bad Hosts – SIP | **176** |
| Bad Hosts – SSH | **3,036** |
| Bad Hosts – RDP | **831** |
| Bad Hosts – MSSQL | **484** |
| Bad Hosts – HTTP | **3,579** |
| Bad Hosts – VNC | **334** |
| Bad Hosts – SNMP | **350** |
| Bad Hosts – TFTP | **204** |
| Bad Hosts – ProConOs | **142** |
| Bad Hosts – Telnet | **2,878** |
| Bad Hosts – PostgreSQL | **411** |
| Bad Hosts – MySQL | **656** |
| Bad Hosts – FTP | **500** |
| Bad Hosts – Kubernetes | **696** |
| Bad Hosts – Elasticsearch | **548** |
| Bad Hosts – Redis | **443** |
| Bad Hosts – CouchDB | **210** |
| Bad Hosts – ClickhouseHTTP | **234** |
| Bad Hosts – Oracle | **266** |
| Bad Hosts – Modbus | **181** |
| Bad Hosts – Memcached | **194** |
| Bad Hosts – RAW | **116** |
| Bad Hosts – MQTT | **197** |
| Bad Hosts – LDAP | **199** |
| Bad Hosts – IPP | **86** |
| Bad Hosts – LPD | **59** |
| Bad Hosts – HashCountRandom | **33** |
| Bad Hosts – MOTD | **18** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **459** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **459** |
| 2026-09-25 | **10,541** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,457** |
| Kandidaten dieses Abrufs | **13,457** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+351** |
| Entfernt | **-367** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-26 02:25 CEST (Berlin)*