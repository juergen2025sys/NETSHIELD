# Honigtopf – Report
**Aktualisiert:** 2026-10-07 15:12 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-07 15:12 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,821** |
| Bad Hosts – SIP | **192** |
| Bad Hosts – SSH | **3,723** |
| Bad Hosts – VNC | **553** |
| Bad Hosts – MSSQL | **508** |
| Bad Hosts – HTTP | **3,549** |
| Bad Hosts – RDP | **788** |
| Bad Hosts – SNMP | **410** |
| Bad Hosts – Telnet | **2,579** |
| Bad Hosts – FTP | **571** |
| Bad Hosts – ProConOs | **143** |
| Bad Hosts – MySQL | **705** |
| Bad Hosts – TFTP | **224** |
| Bad Hosts – Redis | **411** |
| Bad Hosts – PostgreSQL | **483** |
| Bad Hosts – Kubernetes | **806** |
| Bad Hosts – Memcached | **268** |
| Bad Hosts – CouchDB | **418** |
| Bad Hosts – Elasticsearch | **659** |
| Bad Hosts – ClickhouseHTTP | **382** |
| Bad Hosts – Oracle | **314** |
| Bad Hosts – RAW | **151** |
| Bad Hosts – Modbus | **191** |
| Bad Hosts – MQTT | **225** |
| Bad Hosts – LDAP | **193** |
| Bad Hosts – IPP | **107** |
| Bad Hosts – HashCountRandom | **99** |
| Bad Hosts – LPD | **56** |
| Bad Hosts – BeaconAPI.web3signer | **30** |
| Bad Hosts – MOTD | **46** |
| Bad Hosts – Docker | **16** |
| Bad Hosts – BitcoinRPC.dash | **11** |
| Bad Hosts – XMRigAPI | **18** |
| Bad Hosts – Electrum | **5** |
| Bad Hosts – BitcoinRPC | **4** |
| Bad Hosts – ClaymoreAPI | **6** |
| Bad Hosts – BitcoinP2P | **6** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – BeaconAPI.engine | **1** |
| Bad Hosts – MoneroRPC | **6** |
| Bad Hosts – BitcoinP2P.litecoin | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-07)**: **7,206** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-07 | **7,206** |
| 2026-10-06 | **4,615** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,498** |
| Kandidaten dieses Abrufs | **14,498** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,380** |
| Entfernt | **-1,377** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-07 15:12 CEST (Berlin)*