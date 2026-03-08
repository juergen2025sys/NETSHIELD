# NETSHIELD Firewall Exports

**Aktualisiert:** 2026-03-08 18:12 UTC  
**IPs gesamt:** 0

---

## Verfügbare Formate

| Datei | Format | Verwendung |
|---|---|---|
| `blacklist.json` | JSON | APIs, Skripte, SIEM-Systeme |
| `blacklist.csv` | CSV | Excel, Datenbanken, universell |
| `blacklist_iptables.sh` | iptables | Linux (Ubuntu, Debian, CentOS) |
| `blacklist_nftables.conf` | nftables | Linux (moderner iptables-Ersatz) |
| `blacklist_pfsense_opnsense.xml` | XML Alias | pfSense / OPNsense Import |
| `blacklist_cisco_acl.txt` | Cisco ACL | Cisco IOS / IOS-XE Router |
| `blacklist_mikrotik.rsc` | RouterOS | Mikrotik Router |
| `blacklist_windows_firewall.ps1` | PowerShell | Windows Server / Desktop |

---

## Schnellstart

**Linux iptables:**
```bash
sudo bash blacklist_iptables.sh
```

**Linux nftables:**
```bash
sudo nft -f blacklist_nftables.conf
```

**OPNsense/pfSense:**  
Firewall → Aliases → Import → `blacklist_pfsense_opnsense.xml`

**Mikrotik:**
```
/import file=blacklist_mikrotik.rsc
```

**Windows (Admin PowerShell):**
```powershell
.\blacklist_windows_firewall.ps1
```

---
*Automatisch generiert von NETSHIELD Firewall Format Exporter · 2026-03-08 18:12 UTC*
