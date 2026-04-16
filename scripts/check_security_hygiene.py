#!/usr/bin/env python3
"""
NETSHIELD Security-Hygiene Check
=================================
Standalone-Check der die wichtigsten Regeln zum Supply-Chain- und
Code-Hygiene-Schutz auf einen Schlag durchspielt. Dieser Script
exit 1 bei Verstoß – damit direkt einsetzbar als:

  • Pre-Commit-Hook:
        cp scripts/check_security_hygiene.py .git/hooks/pre-commit
        chmod +x .git/hooks/pre-commit

  • CI-Step in run_tests.yml:
        - name: Security hygiene
          run: python3 scripts/check_security_hygiene.py

  • Lokaler Check:
        python3 scripts/check_security_hygiene.py

Geprüft wird:
    [1] Jede `uses:`-Direktive in .github/workflows/ ist SHA-gepinnt
        (40 Hex-Zeichen, nicht nur ein Tag). Der Check ist der gleiche
        wie in workflow_health_checker.yml:Check 24 – aber als harter
        Fehler, nicht als Warning. Nur dieser lokale Check stoppt einen
        Commit/PR bevor eine ungepinnte Action ins main landet.

    [2] Keine direkten `open(path, "w")`-Aufrufe auf Blacklist-Dateien
        im Top-Level von scripts/ – stattdessen write_ip_list()
        verwenden (atomar).

    [3] Kein `urllib.request.urlopen()` oder `requests.get()` am
        Top-Level von scripts/ – stattdessen fetch_url() verwenden
        (hat SSRF-Schutz).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


# ───────────────────────────────────────────────────────────────
# Konfiguration
# ───────────────────────────────────────────────────────────────

REPO_ROOT      = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR  = REPO_ROOT / ".github" / "workflows"
SCRIPTS_DIR    = REPO_ROOT / "scripts"

SHA40_RE       = re.compile(r"^[a-f0-9]{40}$")
USES_RE        = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.MULTILINE)


# ───────────────────────────────────────────────────────────────
# Check 1: Actions SHA-gepinnt
# ───────────────────────────────────────────────────────────────

def check_action_pinning() -> list[str]:
    """Prüft jede `uses:` in .github/workflows/ auf SHA-Pin."""
    errors: list[str] = []
    if not WORKFLOWS_DIR.is_dir():
        return errors

    for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
        content = wf.read_text(encoding="utf-8")
        lines   = content.splitlines()
        for m in USES_RE.finditer(content):
            action = m.group(1).strip()

            # Zeile auf Kommentar prüfen (Kommentierte `uses:` ignorieren)
            line_no   = content[: m.start()].count("\n")
            line_text = lines[line_no] if line_no < len(lines) else ""
            if line_text.lstrip().startswith("#"):
                continue

            # Lokale Composite Actions (./.github/actions/xxx) → OK
            if "/" not in action:
                continue

            # Kein @ angegeben → harter Fehler
            if "@" not in action:
                errors.append(
                    f"{wf.relative_to(REPO_ROOT)}:{line_no + 1}: "
                    f"'{action}' ohne Version/SHA")
                continue

            ref = action.split("@", 1)[1]

            # Dynamische Expressions durchlassen (Hoffnung auf Laufzeit-Input)
            if ref.startswith("$"):
                continue

            # HARDER CHECK: nur echtes 40-Hex-SHA akzeptieren.
            if not SHA40_RE.match(ref):
                errors.append(
                    f"{wf.relative_to(REPO_ROOT)}:{line_no + 1}: "
                    f"'{action}' ist nicht SHA-gepinnt "
                    f"(ref='{ref}', erwartet: 40 Hex-Zeichen)")
    return errors


# ───────────────────────────────────────────────────────────────
# Check 2: Keine non-atomaren open(..., "w") auf Blacklist-Dateien
# ───────────────────────────────────────────────────────────────

# Dateinamen-Pattern: *.txt Blacklists im Repo-Root
BLACKLIST_TXT_RE = re.compile(
    r"""open\s*\(\s*["'][^"']*\.txt["']\s*,\s*["']w["']""", re.VERBOSE)


def check_atomic_writes() -> list[str]:
    """Warnt wenn direkt open(..., 'w') auf *.txt gemacht wird."""
    errors: list[str] = []
    if not SCRIPTS_DIR.is_dir():
        return errors

    for py in sorted(SCRIPTS_DIR.rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            if BLACKLIST_TXT_RE.search(line):
                errors.append(
                    f"{py.relative_to(REPO_ROOT)}:{i}: direktes "
                    f"open(…, 'w') auf *.txt – stattdessen write_ip_list()")
    return errors


# ───────────────────────────────────────────────────────────────
# Check 3: Keine ungeschützten HTTP-Fetches in scripts/
# ───────────────────────────────────────────────────────────────

def check_fetch_usage() -> list[str]:
    """Warnt wenn urllib.request.urlopen oder requests.* direkt verwendet
    werden – stattdessen fetch_url() (SSRF-geschützt).

    AST-basiert, damit Beispiele in Docstrings/Kommentaren nicht matchen.
    """
    import ast

    errors: list[str] = []
    if not SCRIPTS_DIR.is_dir():
        return errors

    for py in sorted(SCRIPTS_DIR.rglob("*.py")):
        if "__pycache__" in py.parts or py.name == "netshield_common.py":
            # netshield_common.py enthält die abgesicherte Implementierung
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _qualified_name(node.func)
            if name in {
                "urllib.request.urlopen",
                "requests.get", "requests.post", "requests.put",
                "requests.delete", "requests.head", "requests.request",
            }:
                errors.append(
                    f"{py.relative_to(REPO_ROOT)}:{node.lineno}: "
                    f"direkter {name}(...) – stattdessen fetch_url() "
                    f"(SSRF-geschützt)")
    return errors


def _qualified_name(node):
    """ast-Hilfe: 'a.b.c' aus ast.Attribute(a.b.c) rekonstruieren."""
    import ast
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


# ───────────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────────

def main() -> int:
    all_errors: list[tuple[str, list[str]]] = []

    checks = [
        ("Actions SHA-Pinning",               check_action_pinning),
        ("Atomare Writes auf Blacklisten",    check_atomic_writes),
        ("SSRF-geschützte HTTP-Fetches",      check_fetch_usage),
    ]

    for name, fn in checks:
        errs = fn()
        status = "PASS" if not errs else f"FAIL ({len(errs)})"
        print(f"[{status}] {name}")
        if errs:
            all_errors.append((name, errs))

    if not all_errors:
        print("\n✓ Alle Security-Hygiene-Checks bestanden.")
        return 0

    print("\n" + "═" * 70)
    print("FEHLGESCHLAGENE CHECKS:")
    print("═" * 70)
    for name, errs in all_errors:
        print(f"\n[{name}]")
        for e in errs:
            print(f"  • {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
