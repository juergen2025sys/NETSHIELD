# Honigtopf – Report
**Aktualisiert:** 2026-10-02 01:10 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ unklar (410) – im Pool belassen |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 01:10 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,443** |
| Bad Hosts – SIP | **165** |
| Bad Hosts – SSH | **3,106** |
| Bad Hosts – RDP | **695** |
| Bad Hosts – MSSQL | **486** |
| Bad Hosts – HTTP | **3,194** |
| Bad Hosts – SNMP | **389** |
| Bad Hosts – VNC | **359** |
| Bad Hosts – MySQL | **663** |
| Bad Hosts – ProConOs | **131** |
| Bad Hosts – Telnet | **3,008** |
| Bad Hosts – FTP | **533** |
| Bad Hosts – TFTP | **191** |
| Bad Hosts – PostgreSQL | **308** |
| Bad Hosts – Kubernetes | **644** |
| Bad Hosts – Redis | **371** |
| Bad Hosts – Elasticsearch | **536** |
| Bad Hosts – CouchDB | **255** |
| Bad Hosts – Oracle | **250** |
| Bad Hosts – ClickhouseHTTP | **231** |
| Bad Hosts – Modbus | **188** |
| Bad Hosts – Memcached | **213** |
| Bad Hosts – MQTT | **199** |
| Bad Hosts – LDAP | **161** |
| Bad Hosts – IPP | **85** |
| Bad Hosts – HashCountRandom | **154** |
| Bad Hosts – RAW | **91** |
| Bad Hosts – LPD | **59** |
| Bad Hosts – MOTD | **70** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-01)**: **10,095** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **2** |
| 2026-10-01 | **10,095** |
| 2026-09-30 | **346** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,076** |
| Kandidaten dieses Abrufs | **13,076** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+805** |
| Entfernt | **-1,082** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 01:10 CEST (Berlin)*