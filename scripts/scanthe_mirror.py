#!/usr/bin/env python3
"""
ScanThe.Net Mirror
==================
Holt die Cloudflare-geschuetzte Blocklist `https://blacklist.scanthe.net/daily`
ueber einen echten Headless-Browser (Playwright/Chromium), der die
Cloudflare-Challenge durchlaeuft, extrahiert die IPs und schreibt sie als
simple Liste `scanthe_daily.txt` ins Repo.

NETSHIELD und OPNsense ziehen dann von der Repo-Datei ueber
raw.githubusercontent.com -> dort gibt es keine Cloudflare-Wall.

WARTUNGSHINWEIS: Cloudflare-Challenges aendern sich. Bricht der Scraper
(0 IPs / dauerhaftes Interstitial), ist DIES die Stelle zum Nachpflegen:
ggf. `playwright-stealth` ergaenzen oder die Warte-/Selektor-Logik anpassen.
Solange < MIN_IPS extrahiert werden, wird die bestehende Datei NICHT
ueberschrieben (kein Ueberschreiben einer guten Liste mit einer Fehlerseite).
"""
import re
import sys
import ipaddress
import pathlib

from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth

URL = "https://blacklist.scanthe.net/daily"
OUT = pathlib.Path("scanthe_daily.txt")
MIN_IPS = 50            # Sanity-Schwelle: darunter wird NICHT geschrieben
NAV_TIMEOUT_MS = 60_000
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CF_MARKERS = ("just a moment", "checking your browser",
              "cf-chl", "challenge-platform", "verify you are human")


def valid_public_v4(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and not (
        a.is_private or a.is_loopback or a.is_reserved
        or a.is_multicast or a.is_link_local or a.is_unspecified
    )


def grab_text() -> str:
    # Stealth().use_sync(...) patcht den Playwright-Kontext: jede hier
    # erstellte Page bekommt automatisch die Anti-Detection-Evasions
    # (navigator.webdriver, Plugins, WebGL-Vendor etc.), an denen Cloudflare
    # einen Headless-Chromium sonst erkennt.
    with Stealth().use_sync(sync_playwright()) as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox",
                  "--disable-blink-features=AutomationControlled"],
        )
        ctx = browser.new_context(
            user_agent=UA, locale="en-US",
            viewport={"width": 1280, "height": 800},
        )
        page = ctx.new_page()
        text = ""
        for attempt in range(1, 5):
            try:
                page.goto(URL, wait_until="domcontentloaded",
                          timeout=NAV_TIMEOUT_MS)
            except Exception as e:  # noqa: BLE001
                print(f"Versuch {attempt}: Navigation fehlgeschlagen ({e})",
                      file=sys.stderr)
                continue
            # Warten bis das Cloudflare-Interstitial verschwindet und echte
            # Inhalte (IPs) im Body stehen.
            for _ in range(20):
                body = page.inner_text("body") or ""
                low = body.lower()
                if not any(m in low for m in CF_MARKERS) and IPV4.search(body):
                    text = body
                    break
                page.wait_for_timeout(1500)
            if text:
                break
            print(f"Versuch {attempt}: Cloudflare-Interstitial noch aktiv, "
                  f"neuer Versuch ...", file=sys.stderr)
            page.wait_for_timeout(3000)
        browser.close()
        return text


def main() -> int:
    text = grab_text()
    ips = sorted(
        {ip for ip in IPV4.findall(text) if valid_public_v4(ip)},
        key=lambda s: tuple(int(o) for o in s.split(".")),
    )
    print(f"extrahierte gueltige oeffentliche IPv4: {len(ips)}")
    if len(ips) < MIN_IPS:
        print(f"FEHLER: nur {len(ips)} IPs (< {MIN_IPS}) - vermutlich "
              f"Cloudflare-Block oder leere Antwort. Bestehende Datei bleibt "
              f"unveraendert.", file=sys.stderr)
        return 1
    header = ("# ScanThe.Net daily - Mirror via Headless-Browser\n"
              f"# Quelle: {URL}\n"
              f"# IPs: {len(ips)}\n")
    OUT.write_text(header + "\n".join(ips) + "\n")
    print(f"geschrieben: {OUT} ({len(ips)} IPs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
