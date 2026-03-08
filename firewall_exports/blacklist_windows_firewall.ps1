# NETSHIELD Blacklist – Windows Firewall (PowerShell)
# Aktualisiert: 2026-03-08 18:12 UTC
# Eintraege: 0
# Ausfuehren als Administrator: .\blacklist_windows_firewall.ps1

# Bestehende NETSHIELD-Regel entfernen
Remove-NetFirewallRule -DisplayName "NETSHIELD_Blacklist" -ErrorAction SilentlyContinue

# Alle IPs als einzelne Blockliste hinzufuegen
$ips = @(
)

New-NetFirewallRule `
    -DisplayName "NETSHIELD_Blacklist" `
    -Direction Inbound `
    -Action Block `
    -RemoteAddress $ips `
    -Description "NETSHIELD Combined Threat Blacklist – 2026-03-08 18:12 UTC"

Write-Host "NETSHIELD Blacklist geladen: $($ips.Count) IPs geblockt"
