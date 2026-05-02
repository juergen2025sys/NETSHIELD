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

    [4] Jeder Workflow hat `timeout-minutes:` gesetzt (auf job- oder
        step-Ebene). Ohne Timeout haengt ein failender Runner bis zum
        6h-GitHub-Default und blockiert die Concurrency-Group.

    [5] Jeder Workflow hat `permissions:` am Top-Level gesetzt. Ohne
        Deklaration erbt der Workflow das Default-Token mit Schreib-
        rechten auf das gesamte Repo – verletzt Least-Privilege.

    [6] Jeder Workflow der `git push` ausfuehrt hat einen Retry-Loop
        (Kombination aus `for attempt`/`while` + `git rebase`). Ohne
        Retry schlagen parallele Scheduler-Runs silent fehl, wenn ein
        anderer Job kurz davor gepusht hat.
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

# FIX PYYAML-SKIP: von check_workflow_timeouts/permissions/push_retry gesetzt
# wenn PyYAML nicht installiert ist. main() zeigt dann einen INFO-Hinweis
# aber laesst die Checks nicht als FAIL durchfallen.
_yaml_missing = False


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
            # FIX QUOTE-STRIP: YAML erlaubt Quotes um den uses:-Wert
            # ("uses: 'actions/checkout@<sha>'" oder "...@<sha>"). Vorher
            # nahm m.group(1).strip() die Quotes mit, ref hatte ein
            # trailing " oder ', SHA40_RE matchte nicht und der Check
            # meldete echte SHA-gepinnte Actions als 'nicht gepinnt'.
            action = m.group(1).strip().strip("'\"")

            # Zeile auf Kommentar prüfen (Kommentierte `uses:` ignorieren)
            line_no   = content[: m.start()].count("\n")
            line_text = lines[line_no] if line_no < len(lines) else ""
            if line_text.lstrip().startswith("#"):
                continue

            # Lokale Composite Actions (./.github/actions/xxx oder ../...) → OK
            # FIX LOCAL-COMPOSITE: lokale Pfade haben einen '/' drin, der alte
            # Check "if '/' not in action" hat sie NICHT übersprungen sondern
            # als non-pinned gemeldet. Jetzt explizit auf './' / '../' prüfen.
            if action.startswith(("./", "../")):
                continue
            # Kein '/' → vermutlich reusable-workflow-name ohne Pfad → OK
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
# Check 2: Keine non-atomaren open(..., "w"/"a") auf Daten-Dateien
# ───────────────────────────────────────────────────────────────
#
# FIX CHK2-AST (2026-04): von Regex auf AST umgebaut. Der alte Regex
# (r'''open\s*\(\s*["'][^"']*\.txt["']...''') matcht nur Literal-Pfade
# wie open("foo.txt", "w"), aber NICHT Variable-Pfade wie
# open(OUT_FILE, "w"). Dadurch waren über Jahre 15 non-atomare Writes
# in den Workflows unentdeckt geblieben. Der AST-Check findet beides.
#
# Bewusste Append-Stellen (z.B. FIX RACE2 in community_ip_report.yml)
# koennen mit einem '# allow-nonatomic: <grund>'-Kommentar in derselben
# Zeile markiert werden – diese werden vom Check uebersprungen.

# Modi die als "schreibend" gelten und atomar erfolgen muessen.
# 'r', 'rt', 'rb' etc. sind ausgeschlossen.
_WRITE_MODES = {"w", "wb", "wt", "w+", "a", "ab", "at", "a+", "x", "xb", "xt"}

# Modus-Konstanten die keine atomare Garantie brauchen (Scratch/Stdin-Stream).
_SAFE_TARGETS = {
    "/dev/null", "/dev/stdout", "/dev/stderr",
    # GitHub-Action-Outputs sind kurze Key=Value-Files die auch bei
    # Teilausfall funktional brauchbar sind (GHA liest Zeilenweise).
    # Trotzdem ggf. atomar schreiben empfohlen.
}

# Marker-Kommentar fuer bewusste Ausnahmen
_ALLOW_COMMENT = "allow-nonatomic"


def _extract_string_from_node(node):
    """Versucht aus einem AST-Node einen String zu extrahieren.

    Gibt None zurueck wenn der Pfad nicht statisch bestimmbar ist.
    Unterstuetzt: Literal, f-String mit ausschliesslich konstanten Parts,
    und Name-Referenzen auf Modul-Level-Konstanten (werden spaeter
    vom Aufrufer aufgeloest).
    """
    import ast as _ast
    if isinstance(node, _ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, _ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, _ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                return None  # dynamischer Teil – Pfad nicht bestimmbar
        return "".join(parts)
    return None


def _suggest_helper(path_str):
    """Liefert eine passende Fix-Empfehlung anhand der Dateiendung."""
    if path_str is None:
        return "write_text_atomic() / write_ip_list() / write_json_atomic()"
    lower = path_str.lower()
    if lower.endswith(".json"):
        return "write_json_atomic()"
    if lower.endswith(".txt"):
        return "write_ip_list() oder write_text_atomic()"
    return "write_text_atomic()"


def _line_has_allow_marker(lines, line_1indexed, end_line_1indexed=None):
    """True wenn die Python-Quell-Zeile oder eine der bis zu 3 vorigen
    Zeilen einen '# allow-nonatomic: <grund>'-Kommentar enthaelt.

    FIX MULTILINE-MARKER: bei multi-line open(...) Calls kann der Marker
    auch hinter dem schliessenden ')' stehen. Wenn end_line_1indexed
    uebergeben wird, werden die Zeilen vom Start des Calls bis zum Ende
    geprueft, zusaetzlich zu 3 Zeilen davor.

    Mehrzeilige Kommentar-Bloecke werden toleriert – der Marker kann
    also am Anfang eines 2-3-Zeilen-Kommentars stehen und der Call
    darunter.
    """
    scan_lines = set()
    # 3 Zeilen vor dem Start
    for ln in range(line_1indexed - 3, line_1indexed + 1):
        scan_lines.add(ln)
    # Plus alle Zeilen des Calls bis zum Ende (multi-line open())
    if end_line_1indexed is not None and end_line_1indexed >= line_1indexed:
        for ln in range(line_1indexed, end_line_1indexed + 1):
            scan_lines.add(ln)
    for ln in scan_lines:
        if 1 <= ln <= len(lines):
            if _ALLOW_COMMENT in lines[ln - 1]:
                return True
    return False


def _resolve_path_arg(arg_node, static_strings):
    """Pfad-Resolution aus einem AST-Argument: Konstante > Name → static_strings."""
    import ast as _ast
    s = _extract_string_from_node(arg_node)
    if s is not None:
        return s
    if isinstance(arg_node, _ast.Name):
        return static_strings.get(arg_node.id)
    return None


def _resolve_pathlib_receiver(receiver, static_strings):
    """Pfad aus pathlib-Receiver: Path("x").attr(...) oder p.attr(...).

    Liefert None wenn der Pfad nicht statisch bestimmbar ist – der Aufrufer
    meldet dann '<Variable>' wie bei builtin open(VAR, "w").
    """
    import ast as _ast
    if isinstance(receiver, _ast.Call) and receiver.args:
        # Path("foo.txt").open(...) – 1. Arg des Konstruktor-Calls ist Pfad
        return _resolve_path_arg(receiver.args[0], static_strings)
    if isinstance(receiver, _ast.Name):
        # X.open(...) wo X = "foo.txt" als Modul-Konstante
        return static_strings.get(receiver.id)
    return None


def _find_non_atomic_writes_in_src(source_text):
    """Findet alle non-atomaren Write-Calls per AST-Walk.

    Erkennt drei Patterns:
        (1) builtin open(path, mode) mit Schreib-Mode
        (2) pathlib X.open(mode) mit Schreib-Mode (FIX PATHLIB-DETECT)
        (3) pathlib X.write_text(...) / X.write_bytes(...) (FIX PATHLIB-DETECT)

    FIX PATHLIB-DETECT: Vorher wurde nur Pattern 1 erfasst
    (isinstance(node.func, ast.Name) and node.func.id == "open"). Pathlib-
    aequivalente Writes blieben unsichtbar, obwohl sie genauso non-atomar
    sind (open-write-close ohne tmpfile+rename).

    Returns:
        list[tuple[int, str|None, str]]: (lineno, path_or_None, mode_label)
    """
    import ast as _ast
    try:
        tree = _ast.parse(source_text)
    except SyntaxError:
        return []

    # Modul-Level-Konstanten sammeln: NAME = "/path/to/file"
    static_strings = {}
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, _ast.Name):
                extracted = _extract_string_from_node(node.value)
                if extracted is not None:
                    static_strings[target.id] = extracted

    findings = []
    src_lines = source_text.splitlines()
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue

        path_str = None
        mode_label = None

        # Pattern 1: builtin open(path, mode) ODER open(path, mode="w")
        if isinstance(node.func, _ast.Name) and node.func.id == "open":
            if not node.args:
                continue
            # FIX KW-MODE: mode kann positional ODER keyword sein. Vorher
            # wurde nur node.args[1] geprueft – open("x", mode="w") rutschte
            # durch, exakt das non-atomare Pattern was der Check finden soll.
            mode_arg = None
            if len(node.args) >= 2:
                mode_arg = node.args[1]
            else:
                for kw in node.keywords:
                    if kw.arg == "mode":
                        mode_arg = kw.value
                        break
            if mode_arg is None:
                continue
            if not (isinstance(mode_arg, _ast.Constant)
                    and isinstance(mode_arg.value, str)
                    and mode_arg.value in _WRITE_MODES):
                continue
            mode_label = mode_arg.value
            path_arg = node.args[0]
            path_str = _resolve_path_arg(path_arg, static_strings)

        # Pattern 2 & 3: pathlib-style X.attr(...)
        elif isinstance(node.func, _ast.Attribute):
            attr = node.func.attr
            if attr == "open":
                # Path("x").open("w") oder Path("x").open(mode="w")
                # FIX KW-MODE: Konsistent zu Pattern 1 auch keyword unterstuetzen.
                mode_arg = None
                if node.args:
                    mode_arg = node.args[0]
                else:
                    for kw in node.keywords:
                        if kw.arg == "mode":
                            mode_arg = kw.value
                            break
                if mode_arg is None:
                    continue
                if not (isinstance(mode_arg, _ast.Constant)
                        and isinstance(mode_arg.value, str)
                        and mode_arg.value in _WRITE_MODES):
                    continue
                mode_label = mode_arg.value
                path_str = _resolve_pathlib_receiver(node.func.value, static_strings)
            elif attr in ("write_text", "write_bytes"):
                # Path.write_text(...) ist immer non-atomar (single
                # open-write-close). Kein Mode-Arg, label aus dem Methodennamen.
                mode_label = "w" if attr == "write_text" else "wb"
                path_str = _resolve_pathlib_receiver(node.func.value, static_strings)
            else:
                continue
        else:
            continue

        # Allow-Marker im Quelltext
        end_ln = getattr(node, "end_lineno", None)
        if _line_has_allow_marker(src_lines, node.lineno, end_ln):
            continue

        # Safe-Targets ausnehmen (z.B. /dev/null)
        if path_str in _SAFE_TARGETS:
            continue

        findings.append((node.lineno, path_str, mode_label))
    return findings


def check_atomic_writes() -> list[str]:
    """Warnt wenn direkt open(..., 'w'/'a'/'x') verwendet wird – statt
    write_ip_list() / write_text_atomic() / write_json_atomic().

    AST-basiert: findet sowohl open("foo.txt", "w") als auch
    open(VAR, "w"). Ausnahme per '# allow-nonatomic: <grund>'-Kommentar.

    Prueft scripts/*.py (ausser netshield_common.py, die die atomaren
    Helper selbst definiert) und Inline-Python in Workflows.
    """
    errors: list[str] = []

    def _report(origin, lineno, path_str, mode):
        path_display = path_str if path_str is not None else "<Variable>"
        helper = _suggest_helper(path_str)
        errors.append(
            f"{origin}:{lineno}: direktes open({path_display!r}, {mode!r}) "
            f"– stattdessen {helper}")

    # --- scripts/*.py ---
    if SCRIPTS_DIR.is_dir():
        for py in sorted(SCRIPTS_DIR.rglob("*.py")):
            if "__pycache__" in py.parts or py.name == "netshield_common.py":
                continue
            source = py.read_text(encoding="utf-8")
            origin = str(py.relative_to(REPO_ROOT))
            for lineno, path_str, mode in _find_non_atomic_writes_in_src(source):
                _report(origin, lineno, path_str, mode)

    # --- Inline-Python in Workflows ---
    if WORKFLOWS_DIR.is_dir():
        # FIX HEREDOC-FLAGS: '-?' matchte vorher nur ein einzelnes '-'.
        # 'python3 -u << EOF' (unbuffered, sehr verbreitet in CI) und
        # 'python3 -B << EOF' rutschten durch. Jetzt beliebig viele
        # Single-Char- oder Multi-Char-Flags zulassen.
        heredoc_start = re.compile(
            r"python3(?:\s+-\w+)*\s*<<\s*['\"]?(\w+)['\"]?\s*$", re.MULTILINE)
        import textwrap as _tw
        for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
            content = wf.read_text(encoding="utf-8")
            lines = content.splitlines()
            i = 0
            while i < len(lines):
                m = heredoc_start.search(lines[i])
                if not m:
                    i += 1
                    continue
                delim = m.group(1)
                block_start_lineno = i + 2  # +1 fuer 1-indexed, +1 fuer EOF-Zeile
                i += 1
                block = []
                while i < len(lines):
                    if lines[i].strip() == delim:
                        break
                    block.append(lines[i])
                    i += 1
                i += 1  # EOF-Zeile ueberspringen
                if not block:
                    continue
                source = _tw.dedent("\n".join(block))
                origin = str(wf.relative_to(REPO_ROOT))
                for src_lineno, path_str, mode in _find_non_atomic_writes_in_src(source):
                    yaml_lineno = block_start_lineno + src_lineno - 1
                    _report(origin, yaml_lineno, path_str, mode)

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

        def _is_static_url_node(n):
            """True wenn n ein AST-Node mit statischer URL-Konstante ist."""
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                return n.value.startswith(("http://", "https://"))
            if isinstance(n, ast.JoinedStr) and n.values:
                first = n.values[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    return first.value.startswith(("http://", "https://"))
            return False

        # Modul-Level-Konstanten sammeln: NAME = "https://..."
        # FIX STATIC-URL: Auch f-Strings mit statischem Prefix als Konstante zaehlen.
        static_url_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and _is_static_url_node(node.value):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        static_url_names.add(tgt.id)

        # Request(...)-Aufrufe wo 1. Arg statische URL ODER bekannte URL-Variable ist
        # FIX STATIC-URL: Der alte Code trackte nur Request(NAME), nicht
        # Request("literal"). Jetzt beide Formen.
        request_via_static_var = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                cn = _qualified_name(node.value.func)
                if cn in ("urllib.request.Request", "Request") and node.value.args:
                    a0 = node.value.args[0]
                    is_static = (
                        _is_static_url_node(a0)
                        or (isinstance(a0, ast.Name) and a0.id in static_url_names)
                    )
                    if is_static:
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
            # urlopen(VAR) wobei VAR statische URL-Konstante ODER Request(static) ist → erlaubt
            # FIX STATIC-URL: alter Code fragte nur request_via_static_var ab,
            # static_url_names wurde aufgebaut aber nie benutzt.
            if node.args and isinstance(node.args[0], ast.Name):
                if node.args[0].id in static_url_names:
                    continue
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
        # FIX HEREDOC-FLAGS: konsistent zu check_atomic_writes – auch
        # python3 -u/-B/-X… erkennen.
        heredoc_re = re.compile(
            r"python3(?:\s+-\w+)*\s*<<\s*['\"]?(\w+)['\"]?\s*$",
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
# Check 4: timeout-minutes auf jedem Workflow
# ───────────────────────────────────────────────────────────────

def check_workflow_timeouts() -> list[str]:
    """Warnt wenn ein Workflow keinen `timeout-minutes:` auf job-Ebene hat.

    Ohne Timeout laeuft ein haengender Runner bis zum 6h-GitHub-Default.
    Bei Workflows in der `netshield-seen-db-writers`-Concurrency-Group
    blockiert das alle anderen seen_db-Schreiber fuer bis zu 6 Stunden.

    Prueft auf dict-Ebene: jeder Job muss timeout-minutes haben ODER der
    Workflow hat es als Default gesetzt. Reine Text-Suche reicht nicht,
    weil `timeout-minutes` auch in Kommentaren stehen koennte.
    """
    errors: list[str] = []
    if not WORKFLOWS_DIR.is_dir():
        return errors

    try:
        import yaml
    except ImportError:
        # FIX PYYAML-SKIP: alter Code returnte ["(Check 4 uebersprungen: ...)"]
        # was main() als FAIL interpretierte. Skip ohne Error-Eintrag, stattdessen
        # via globalem Flag in main() anzeigen.
        global _yaml_missing
        _yaml_missing = True
        return errors

    for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
        try:
            data = yaml.safe_load(wf.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            errors.append(f"{wf.relative_to(REPO_ROOT)}: YAML-Parse-Fehler: {e}")
            continue
        if not isinstance(data, dict):
            continue

        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            continue

        jobs_without_timeout = []
        for job_name, job_def in jobs.items():
            if not isinstance(job_def, dict):
                continue
            # reusable-workflow job (uses:) kann keinen timeout-minutes haben
            if "uses" in job_def:
                continue
            if "timeout-minutes" not in job_def:
                jobs_without_timeout.append(job_name)

        if jobs_without_timeout:
            errors.append(
                f"{wf.relative_to(REPO_ROOT)}: "
                f"Jobs ohne timeout-minutes: {', '.join(jobs_without_timeout)} "
                f"- ohne Timeout laeuft ein haengender Runner bis 6h")
    return errors


# ───────────────────────────────────────────────────────────────
# Check 5: permissions am Top-Level
# ───────────────────────────────────────────────────────────────

# Workflows die bewusst keine permissions brauchen (z.B. reine Test-Runner)
# werden mit einem Allow-Marker in der ersten Kommentar-Zeile gekennzeichnet.
_PERMISSIONS_ALLOW_MARKER = "allow-no-permissions"


def check_workflow_permissions() -> list[str]:
    """Warnt wenn ein Workflow kein `permissions:` am Top-Level hat.

    Ohne Deklaration erbt der Workflow das Default-GITHUB_TOKEN – bei
    aelteren Repos mit "write permissions" als Default ein breiter
    Angriffsvektor. Best-Practice: Least-Privilege, explizit setzen.

    Ausnahme-Marker: Wer in der allerersten Zeile '# allow-no-permissions:
    <grund>' setzt, wird uebersprungen.
    """
    errors: list[str] = []
    if not WORKFLOWS_DIR.is_dir():
        return errors

    try:
        import yaml
    except ImportError:
        # FIX PYYAML-SKIP: siehe check_workflow_timeouts
        global _yaml_missing
        _yaml_missing = True
        return errors

    for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
        text = wf.read_text(encoding="utf-8")

        # Ausnahme-Marker in den ersten 3 Zeilen
        first_lines = text.splitlines()[:3]
        if any(_PERMISSIONS_ALLOW_MARKER in ln for ln in first_lines):
            continue

        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict):
            continue

        if "permissions" not in data:
            errors.append(
                f"{wf.relative_to(REPO_ROOT)}: "
                f"kein 'permissions:' am Top-Level – Default-Token "
                f"erbt Schreibrechte. Mit '# allow-no-permissions: <grund>' "
                f"in Zeile 1 ausnahmsweise erlauben.")
    return errors


# ───────────────────────────────────────────────────────────────
# Check 6: git push mit Retry-Loop
# ───────────────────────────────────────────────────────────────

def check_push_retry() -> list[str]:
    """Warnt wenn ein Workflow `git push` ohne Retry-Loop verwendet.

    Bei parallelen Schedulern (selbe cron-Minute, verschiedene Workflows)
    kann der zweite Push fehlschlagen, weil der Remote inzwischen voraus
    ist. Ohne Retry schlaegt der Job fehl und die aktuellen Aenderungen
    gehen verloren (der naechste Run startet wieder von vorn).

    Best-Practice im Repo: for-Loop ueber attempts + `git rebase -X theirs`
    + sleep mit exponential backoff. 16 Workflows machen das bereits so.

    FIX SCOPE: alter Check suchte Loop und Rebase GLOBAL im ganzen
    Workflow-File. Ein Workflow mit Retry-Job A und unrelated push-Job B
    (ohne Retry) passte durch. Jetzt wird pro run:-Block geprueft.

    FIX SHELL-COMMENTS: alter Check ignorierte nur reine YAML-Kommentar-
    Zeilen (strip().startswith('#')). Zeilen wie `# TODO: git push` oder
    `echo 'in zukunft git push'` loesten False Positives aus. Jetzt
    werden Shell-Kommentar-Zeilen innerhalb run:-Bloecken gefiltert, und
    der Regex verlangt `git push` als echtes Kommando (nach Zeilenstart
    oder Shell-Separator, nicht nach Whitespace irgendwo).
    """
    errors: list[str] = []
    if not WORKFLOWS_DIR.is_dir():
        return errors

    try:
        import yaml
    except ImportError:
        # FIX PYYAML-SKIP
        global _yaml_missing
        _yaml_missing = True
        return errors

    # Restriktiverer Regex: `git push` nur nach Zeilenstart oder echtem
    # Shell-Separator (;, &, |), NICHT nach irgendeinem Whitespace.
    # Verhindert Match in `echo "git push"` und `# TODO: git push`.
    push_line_re = re.compile(r"(?:^|[&|;])\s*git\s+push\b", re.MULTILINE)
    loop_re      = re.compile(r"(for\s+attempt|while\s+\[|attempt\s*=\s*\d)")
    rebase_re    = re.compile(r"git\s+(rebase|pull\s+--rebase)")

    def _strip_shell_comments(run_text):
        """Entfernt Shell-Kommentar-Zeilen aus einem run:-Block."""
        out = []
        for line in run_text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            out.append(line)
        return "\n".join(out)

    for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
        try:
            data = yaml.safe_load(wf.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict):
            continue
        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            continue

        for job_name, job_def in jobs.items():
            if not isinstance(job_def, dict):
                continue
            steps = job_def.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                cleaned = _strip_shell_comments(run)
                if not push_line_re.search(cleaned):
                    continue

                has_loop   = bool(loop_re.search(run))
                has_rebase = bool(rebase_re.search(run))
                if has_loop and has_rebase:
                    continue

                missing = []
                if not has_loop:   missing.append("for/while-Loop")
                if not has_rebase: missing.append("git rebase")
                step_label = step.get("name") or step.get("id") or "<unnamed>"
                errors.append(
                    f"{wf.relative_to(REPO_ROOT)} "
                    f"(job '{job_name}', step '{step_label}'): "
                    f"`git push` ohne Retry-Logik (fehlt: {', '.join(missing)}) "
                    f"– bei paralleler Push-Kollision geht das Update verloren")
    return errors


# ───────────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────────

def main() -> int:
    all_errors: list[tuple[str, list[str]]] = []

    checks = [
        ("Actions SHA-Pinning",               check_action_pinning),
        ("Atomare Writes auf Blacklisten",    check_atomic_writes),
        ("SSRF-geschützte HTTP-Fetches",      check_fetch_usage),
        ("Workflow timeout-minutes gesetzt",  check_workflow_timeouts),
        ("Workflow permissions gesetzt",      check_workflow_permissions),
        ("git push mit Retry-Loop",           check_push_retry),
    ]
    # Checks die PyYAML brauchen (fuer SKIP-Statusanzeige)
    yaml_dependent = {
        "Workflow timeout-minutes gesetzt",
        "Workflow permissions gesetzt",
        "git push mit Retry-Loop",
    }

    for name, fn in checks:
        errs = fn()
        if _yaml_missing and name in yaml_dependent and not errs:
            status = "SKIP"
        else:
            status = "PASS" if not errs else f"FAIL ({len(errs)})"
        print(f"[{status}] {name}")
        if errs:
            all_errors.append((name, errs))

    if _yaml_missing:
        print("[INFO]  PyYAML nicht installiert – 3 Checks uebersprungen "
              "(pip install pyyaml aktiviert sie)")

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
