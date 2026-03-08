#!/bin/bash
# NETSHIELD Blacklist – iptables
# Aktualisiert: 2026-03-08 18:12 UTC | Eintraege: 0
# Verwendung: sudo bash blacklist_iptables.sh

# Bestehende NETSHIELD-Chain leeren
iptables -F NETSHIELD 2>/dev/null || iptables -N NETSHIELD
iptables -C INPUT -j NETSHIELD 2>/dev/null || iptables -I INPUT -j NETSHIELD
iptables -C FORWARD -j NETSHIELD 2>/dev/null || iptables -I FORWARD -j NETSHIELD

# Blacklist-Regeln
