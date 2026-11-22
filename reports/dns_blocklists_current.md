# NETSHIELD – aktuelle DNS-Blocklisten

Stand: **2026-11-22 12:34 UTC**

Es werden nur Listen angezeigt, deren **konkrete Listen-Datei in den letzten 7 Tagen aktualisiert wurde**. Eine frische README oder irgendein anderer Repository-Commit reicht nicht.

**Wichtig:** Der Workflow aktiviert keine Liste automatisch. Er erstellt nur einen Fundbericht mit Raw-Links.

## 💡 Tipp: Diese Listen einbauen

- 🎣 **blazskufca/si-cert-dnsbl** / `domains.txt` - Phishing/Betrug, 974 neue Domains, 0 beliebte  
  `https://raw.githubusercontent.com/blazskufca/si-cert-dnsbl/main/domains.txt`

**Vielleicht - erst pruefen:**

- 🦠 asteroid-99942/apophis-blocklist / `lists/diff_report.txt` - ⚠️ pruefen: 1 beliebte Domain(s) - mshome.net
- 🎣 fisventurous/fisphish / `data/discord-scams.txt` - ⚠️ pruefen: 2 beliebte Domain(s) - freecash.com, serveuser.com
- 🦠 Tagoletta/SiberGuvenlikBaskanligi-API / `data/days-120-domains.txt` - ⚠️ pruefen: 1 beliebte Domain(s) - earn.fm

## Alle Funde

| # | Tipp | Kategorie | Liste | Eintraege | Gesperrt | Neu | Beliebte Domains |
|---:|---|---|---|---:|---:|---:|---|
| 1 | ✅ einbauen | 🎣 Phishing/Betrug | [blazskufca/si-cert-dnsbl](https://github.com/blazskufca/si-cert-dnsbl)<br>[domains.txt](https://raw.githubusercontent.com/blazskufca/si-cert-dnsbl/main/domains.txt) · 0.7 d | 1.720 | 43 % | 974 | 0 ✅ |
| 2 | ⚠️ pruefen | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[diff_report.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/diff_report.txt) · 0.1 d | 6.723 | 72 % | 1.910 | ⚠️ 1: mshome.net |
| 3 | ⚠️ pruefen | 🎣 Phishing/Betrug | [fisventurous/fisphish](https://github.com/fisventurous/fisphish)<br>[discord-scams.txt](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/discord-scams.txt) · 0.4 d | 32.210 | 16 % | 27.195 | ⚠️ 2: freecash.com, serveuser.com |
| 4 | ❌ nein | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[blocklist.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/blocklist.txt) · 0.1 d | 4.492.604 | 61 % | 1.735.099 | ⚠️ 1111: 000webhost.com, 13o.net |
| 5 | ❌ nein | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[blocklist_previous.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/blocklist_previous.txt) · 0.1 d | 4.492.604 | 61 % | 1.735.099 | ⚠️ 1111: 000webhost.com, 13o.net |
| 6 | ❌ nein | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[hosts.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/output/hosts.txt) · 0.1 d | 4.492.604 | 61 % | 1.735.099 | ⚠️ 1111: 000webhost.com, 13o.net |
| 7 | ✅ schon drin | 🛡️ Sicherheit | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[all.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/security/all.txt) · 0.5 d | 77.017 | 100 % | 0 | 0 ✅ |
| 8 | ❌ nein | 🪙 Krypto-Drainer | [fisventurous/fisphish](https://github.com/fisventurous/fisphish)<br>[crypto-drainers.txt](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/crypto-drainers.txt) · 0.8 d | 415.422 | 13 % | 359.591 | ⚠️ 9: deepl.network, digiday.com |
| 9 | ⚠️ pruefen | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[days-120-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/days-120-domains.txt) · 0.0 d | 19.196 | 85 % | 2.943 | ⚠️ 1: earn.fm |
| 10 | ➖ Kopie | 🦠 Malware/C2 | [rosical-labs/SiberGuvenlikBaskanligi-API](https://github.com/rosical-labs/SiberGuvenlikBaskanligi-API)<br>[days-120-domains.txt](https://raw.githubusercontent.com/rosical-labs/SiberGuvenlikBaskanligi-API/main/data/days-120-domains.txt) · 0.3 d | 19.192 | 84 % | 2.966 | ⚠️ 1: earn.fm |
| 11 | ➖ kaum Neues | 🎣 Phishing/Betrug | [0xDanielLopez/phishunt-feed](https://github.com/0xDanielLopez/phishunt-feed)<br>[domains.txt](https://raw.githubusercontent.com/0xDanielLopez/phishunt-feed/main/blocklist/domains.txt) · 0.2 d | 908 | 95 % | 45 | ⚠️ 4: dothome.co.kr, hashnode.dev |
| 12 | ❌ nein | 📢 Werbung/Tracker | [cenk/bad-hosts](https://github.com/cenk/bad-hosts)<br>[bad-hosts-domains](https://raw.githubusercontent.com/cenk/bad-hosts/main/bad-hosts-domains) · 0.5 d | 1.541.159 | 77 % | 356.933 | ⚠️ 2489: 000webhost.com, 071kk.com |
| 13 | ❌ nein | 📢 Werbung/Tracker | [DanielEnki420/dns-blocklist-builder](https://github.com/DanielEnki420/dns-blocklist-builder)<br>[blocklist-all.pihole.txt](https://raw.githubusercontent.com/DanielEnki420/dns-blocklist-builder/main/lists/blocklist-all.pihole.txt) · 2.7 d | 1.603 | 77 % | 364 | ⚠️ 97: 33across.com, addthis.com |
| 14 | ❌ nein | 🎣 Phishing/Betrug | [oo12/SMBBB](https://github.com/oo12/SMBBB)<br>[blocklist.txt](https://raw.githubusercontent.com/oo12/SMBBB/master/blocklist.txt) · 2.8 d | 5.574 | 16 % | 4.663 | ⚠️ 83: all.biz, bingx.com |
| 15 | ➖ kaum Neues | 🦠 Malware/C2 | [Jam0k/Public-Feeds-IOCs](https://github.com/Jam0k/Public-Feeds-IOCs)<br>[domains.txt](https://raw.githubusercontent.com/Jam0k/Public-Feeds-IOCs/main/feeds/full/domains.txt) · 0.9 d | 2.380 | 82 % | 425 | ⚠️ 4: ccwu.cc, dedyn.io |
| 16 | ❌ nein | 📢 Werbung/Tracker | [Owie2711/My-Block-List-adguard-home-](https://github.com/Owie2711/My-Block-List-adguard-home-)<br>[merged.txt](https://raw.githubusercontent.com/Owie2711/My-Block-List-adguard-home-/main/merged.txt) · 0.3 d | 543.139 | 93 % | 39.693 | ⚠️ 1676: 000webhost.com, 071kk.com |
| 17 | ❌ nein | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary/domains.txt) · 0.1 d | 232.928 | 67 % | 77.802 | ⚠️ 17: blsp.at, glorioushop.com |
| 18 | ❌ nein | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/community_active/domains.txt) · 0.2 d | 515.120 | 72 % | 143.537 | ⚠️ 105: 1blu.de, 1fichier.com |
| 19 | ❌ nein | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/community/domains.txt) · 0.3 d | 1.181.343 | 36 % | 752.607 | ⚠️ 105: 1blu.de, 1fichier.com |
| 20 | ➖ kaum Neues | 🛡️ Sicherheit | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[ct.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/security/ct.txt) · 0.5 d | 77.006 | 100 % | 0 | 0 ✅ |
| 21 | ➖ kaum Neues | 🦠 Malware/C2 | [Jam0k/Public-Feeds-IOCs](https://github.com/Jam0k/Public-Feeds-IOCs)<br>[domains.txt](https://raw.githubusercontent.com/Jam0k/Public-Feeds-IOCs/main/feeds/domains.txt) · 0.9 d | 711 | 100 % | 0 | 0 ✅ |
| 22 | ✅ schon drin | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[days-90-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/days-90-domains.txt) · 0.0 d | 13.916 | 100 % | 0 | ⚠️ 1: earn.fm |
| 23 | ➖ Kopie | 🦠 Malware/C2 | [rosical-labs/SiberGuvenlikBaskanligi-API](https://github.com/rosical-labs/SiberGuvenlikBaskanligi-API)<br>[days-90-domains.txt](https://raw.githubusercontent.com/rosical-labs/SiberGuvenlikBaskanligi-API/main/data/days-90-domains.txt) · 0.3 d | 14.007 | 99 % | 93 | ⚠️ 1: earn.fm |
| 24 | ❌ nein | 🎰 Gluecksspiel | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[all.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/gambling/all.txt) · 0.5 d | 893.402 | 28 % | 647.037 | ⚠️ 13: betting.co.zw, betway.co.bw |
| 25 | ❌ nein | 🎰 Gluecksspiel | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[ct.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/gambling/ct.txt) · 0.5 d | 891.795 | 28 % | 645.516 | ⚠️ 6: covers.com, cricbet99.black |
| 26 | ✅ schon drin | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt) · 0.3 d | 139.782 | 100 % | 0 | ⚠️ 17: blsp.at, glorioushop.com |
| 27 | ❌ nein | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[full-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/full-domains.txt) · 0.0 d | 480.800 | 28 % | 343.910 | ⚠️ 27: 1fichier.com, 713mtauburnctcolumbusoh43085.st |
| 28 | ➖ kaum Neues | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[days-60-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/days-60-domains.txt) · 0.0 d | 9.318 | 100 % | 0 | ⚠️ 1: earn.fm |
| 29 | ✅ schon drin | 🦠 Malware/C2 | [cenk/malware-domains](https://github.com/cenk/malware-domains)<br>[domains](https://raw.githubusercontent.com/cenk/malware-domains/main/domains) · 0.2 d | 2.601.342 | 100 % | 0 | ⚠️ 259: 000webhost.com, 0xrpc.io |
| 30 | ❌ nein | 🦠 Malware/C2 | [cenk/malware-domains](https://github.com/cenk/malware-domains)<br>[wildcard-domains](https://raw.githubusercontent.com/cenk/malware-domains/main/wildcard-domains) · 0.2 d | 2.309.124 | 100 % | 0 | ⚠️ 237: 000webhost.com, 0xrpc.io |

## Bedeutung

- **Reihenfolge:** nach Score (Frische am staerksten, Abzuege fuer beliebte Domains, Abdeckung und genutzte Listen). Score, Format, Groesse und Datum stehen in `dns_blocklists_current.json`.
- **Liste:** Repo-Link, darunter die Datei (Link = Download-Adresse fuer Unbound) und ihr Alter in Tagen.
- **Tipp:** ✅ einbauen = Schutz-Kategorie, 0 beliebte Domains, mind. 500 neue · ⚠️ pruefen · ❌ nicht (Gluecksspiel/Erwachsene/Werbung, >5 beliebte Domains) · ➖ bringt kaum Neues oder ist eine Kopie.
- **Kategorie:** erkannt an Dateipfad, Repo-Name/-Beschreibung und am Inhalt (Anteil Gluecksspiel-/Erwachsenen-Namen ab 30 %).
- **✅ schon drin** = URL steht schon in Unbound oder NETSHIELD · **➖ Kopie** = Spiegel einer genutzten Quelle unter anderem Konto · **❔ zu gross** = Datei nicht voll pruefbar.
- **Schon gesperrt / Neu fuer mich:** Abgleich mit allen eigenen Unbound-Listen (eigene URLs + AdGuard, StevenBlack, OISD NSFW, Hagezi Pro++/TIF/DoH-Bypass + Unbound-Wildcard-Domains wie pages.dev/workers.dev), exakt und ueber die Hauptdomain (Wildcard). Score-Abzug ab 80 % (-10) und 95 % (-25) Abdeckung.
- **Beliebte Domains:** Treffer aus den 20.000 meistbesuchten Domains (Tranco). Jeder Treffer waere eine echte Seite. die gesperrt wuerde.
- **Eintraege:** Anzahl Domains in der ganzen Datei (nicht nur Stichprobe).
- **OPNsense direkt = Ja:** Stichprobe besteht zu mindestens 98 % aus reinen Domains/Wildcards.
- **dnsmasq / hosts / adblock:** gefunden, aber nicht als direkte reine Domainliste markiert.
- **Maximal 7 Tage alt:** aeltere Listen werden gar nicht erst im Report ausgegeben.

Der Score sagt nichts darueber aus, ob eine Liste garantiert frei von False Positives ist.
