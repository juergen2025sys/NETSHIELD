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

    Prüft:
        - scripts/*.py (außer netshield_common.py – die enthält die
          abgesicherte Implementierung selbst)
        - Inline-Python-Blöcke in .github/workflows/*.yml zwischen
          'python3 << EOF' und 'EOF' (bzw. PYEOF)
    """
    import ast

    errors: list[str] = []

    def _is_call_with_static_url(node):
        """True wenn Call-Node URL als Konstante/f-String mit nur literalen
        Parts hat. Solche Aufrufe sind kein SSRF-Risiko, weil die URL zur
        Compile-Zeit feststeht und nicht aus Eingaben kommt.

        Akzeptiert:
            - urlopen("https://host/path")
            - urlopen(f"https://host/{cc}")   # interpoliert lokale Variable
            - urlopen(req) wobei req = Request("https://host/...")
        Das letzte ist schwierig – wir begnügen uns damit, urlopen-Aufrufe
        zu erlauben, deren URL oder Request-Argument aus einer statischen
        Top-Level-Konstante im selben Modul kommt.
        """
        if not node.args:
            return False
        arg = node.args[0]
        # Literaler String
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value.startswith(("http://", "https://"))
        # f-String mit nur literalen Start-Parts (host ist fix)
        if isinstance(arg, ast.JoinedStr) and arg.values:
            first = arg.values[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value.startswith(("http://", "https://"))
        # urllib.request.Request-Call mit literalem 1. Arg
        if isinstance(arg, ast.Call):
            inner_name = _qualified_name(arg.func)
            if inner_name in ("urllib.request.Request", "Request") and arg.args:
                inner = arg.args[0]
                if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                    return inner.value.startswith(("http://", "https://"))
                if isinstance(inner, ast.JoinedStr) and inner.values:
                    first = inner.values[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        return first.value.startswith(("http://", "https://"))
        return False

    def _scan_source(source_text, origin_label, line_offset=0):
        """Scannt einen Python-Quelltext per AST und liefert Fehler."""
        try:
            tree = ast.parse(source_text)
        except SyntaxError:
            return
        # Modul-Level-Konstanten sammeln: NAME = "https://..."
        static_url_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if (isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                        and node.value.value.startswith(("http://", "https://"))):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            static_url_names.add(tgt.id)
        # Request(...)-Aufrufe wo 1. Arg eine bekannte Konstante ist
        request_via_static_var = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                cn = _qualified_name(node.value.func)
                if cn in ("urllib.request.Request", "Request") and node.value.args:
                    a0 = node.value.args[0]
                    if isinstance(a0, ast.Name) and a0.id in static_url_names:
                        for tgt in node.targets:
                            if isinstance(tgt, ast.Name):
                                request_via_static_var.add(tgt.id)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _qualified_name(node.func)
            if name not in {
                "urllib.request.urlopen",
                "requests.get", "requests.post", "requests.put",
                "requests.delete", "requests.head", "requests.request",
            }:
                continue
            # Statische URL direkt im Call → erlaubt
            if _is_call_with_static_url(node):
                continue
            # urlopen(req) wobei req aus Request(static_url) stammt → erlaubt
            if node.args and isinstance(node.args[0], ast.Name):
                if node.args[0].id in request_via_static_var:
                    continue
            errors.append(
                f"{origin_label}:{node.lineno + line_offset}: "
                f"direkter {name}(...) mit dynamischer URL "
                f"– stattdessen fetch_url() (SSRF-geschützt)")

    # --- scripts/*.py ---
    if SCRIPTS_DIR.is_dir():
        for py in sorted(SCRIPTS_DIR.rglob("*.py")):
            if "__pycache__" in py.parts or py.name == "netshield_common.py":
                continue
            _scan_source(py.read_text(encoding="utf-8"),
                         str(py.relative_to(REPO_ROOT)))

    # --- Inline-Python in Workflows (nur Info-Liste, kein Fail) ---
    # Workflows haben typischerweise urlopen mit URLs aus hardcoded
    # dicts/consts (SOURCES, HONEYPOT_SOURCES, usw.) – also kein SSRF-
    # Risiko. Der AST kann das aber nicht zuverlaessig entscheiden.
    # Deshalb: scripts/ bleibt hart, Workflows werden nur angezeigt
    # damit neue Stellen bewusst in die Liste kommen.
    global workflow_info  # pragmatisch fuer main()
    workflow_info = []
    if WORKFLOWS_DIR.is_dir():
        heredoc_re = re.compile(
            r"python3\s*-?\s*<<\s*['\"]?(\w+)['\"]?\s*$",
            re.MULTILINE,
        )
        for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
            content = wf.read_text(encoding="utf-8")
            lines = content.splitlines()
            i = 0
            while i < len(lines):
                m = heredoc_re.search(lines[i])
                if not m:
                    i += 1
                    continue
                delim = m.group(1)
                start_line = i + 1
                block = []
                i += 1
                while i < len(lines):
                    stripped = lines[i].strip()
                    if stripped == delim:
                        break
                    block.append(lines[i])
                    i += 1
                i += 1
                if not block:
                    continue
                import textwrap as _tw
                source = _tw.dedent("\n".join(block))
                try:
                    tree = ast.parse(source)
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    name = _qualified_name(node.func)
                    if name in {"urllib.request.urlopen",
                                "requests.get", "requests.post",
                                "requests.put", "requests.delete",
                                "requests.head", "requests.request"}:
                        workflow_info.append(
                            f"{wf.relative_to(REPO_ROOT)}:{node.lineno + start_line}: "
                            f"{name}(...) in inline-Python – URLs sollten aus "
                            f"hardcoded dict kommen (Review empfohlen)")

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

    # Info-Block: Workflow-inline urlopen-Aufrufe (nicht fatal)
    wi = globals().get("workflow_info", [])
    if wi:
        print(f"[INFO]  {len(wi)} urlopen(...) in Workflow-Inline-Python "
              f"(URLs aus hardcoded dicts – Review empfohlen, kein Fail)")

    if not all_errors:
        print("\n✓ Alle Security-Hygiene-Checks bestanden.")
        if wi:
            print("\nINFO – Workflow-Inline-Fetches:")
            for e in wi:
                print(f"  • {e}")
        return 0

    print("\n" + "═" * 70)
    print("FEHLGESCHLAGENE CHECKS:")
    print("═" * 70)
    for name, errs in all_errors:
        print(f"\n[{name}]")
        for e in errs:
            print(f"  • {e}")
    if wi:
        print("\n[INFO – Workflow-Inline-Fetches (kein Fail)]")
        for e in wi:
            print(f"  • {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
