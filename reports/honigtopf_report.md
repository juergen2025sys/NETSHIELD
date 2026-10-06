# Honigtopf – Report
**Aktualisiert:** 2026-10-06 19:02 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 19:02 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,583** |
| Bad Hosts – SIP | **167** |
| Bad Hosts – SSH | **3,764** |
| Bad Hosts – SNMP | **406** |
| Bad Hosts – MSSQL | **508** |
| Bad Hosts – RDP | **809** |
| Bad Hosts – TFTP | **213** |
| Bad Hosts – VNC | **338** |
| Bad Hosts – HTTP | **3,686** |
| Bad Hosts – Telnet | **2,625** |
| Bad Hosts – FTP | **560** |
| Bad Hosts – MySQL | **646** |
| Bad Hosts – Memcached | **229** |
| Bad Hosts – ProConOs | **158** |
| Bad Hosts – Kubernetes | **901** |
| Bad Hosts – Redis | **451** |
| Bad Hosts – PostgreSQL | **528** |
| Bad Hosts – CouchDB | **390** |
| Bad Hosts – ClickhouseHTTP | **351** |
| Bad Hosts – Elasticsearch | **676** |
| Bad Hosts – Oracle | **266** |
| Bad Hosts – Modbus | **219** |
| Bad Hosts – LDAP | **276** |
| Bad Hosts – MQTT | **260** |
| Bad Hosts – RAW | **159** |
| Bad Hosts – LPD | **94** |
| Bad Hosts – HashCountRandom | **102** |
| Bad Hosts – IPP | **114** |
| Bad Hosts – MOTD | **79** |
| Bad Hosts – Docker | **5** |
| Bad Hosts – BitcoinRPC | **1** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – ClaymoreAPI | **1** |
| Bad Hosts – BitcoinP2P | **1** |
| Bad Hosts – BeaconAPI.web3signer | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **9,097** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **9,097** |
| 2026-10-05 | **2,486** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,127** |
| Kandidaten dieses Abrufs | **14,127** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+222** |
| Entfernt | **-362** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 19:02 CEST (Berlin)*