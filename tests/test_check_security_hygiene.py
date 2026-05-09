#!/usr/bin/env python3
"""
Tests fuer scripts/check_security_hygiene.py.

Aktuell deckt nur die FIX PATHLIB-DETECT Regression ab; weitere Checks
koennen hier ergaenzt werden.

Ausfuehren:
    python3 -m pytest tests/test_check_security_hygiene.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from check_security_hygiene import _find_non_atomic_writes_in_src


class TestPathlibDetection(unittest.TestCase):
    """FIX PATHLIB-DETECT: Vorher wurde nur builtin open(...) erkannt.
    Path("x").open("w"), Path("x").write_text(), .write_bytes() rutschten
    durch, sind aber genauso non-atomar."""

    def test_builtin_open_still_detected(self):
        """Regression-Sanity: builtin open(...) bleibt detektiert."""
        src = 'open("foo.txt", "w").write("x")\n'
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0][1], "foo.txt")
        self.assertEqual(f[0][2], "w")

    def test_pathlib_open_with_write_mode(self):
        src = (
            'from pathlib import Path\n'
            'Path("foo.txt").open("w").write("x")\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(len(f), 1, f"Erwartet 1 Finding, bekam {f}")
        self.assertEqual(f[0][1], "foo.txt")
        self.assertEqual(f[0][2], "w")

    def test_pathlib_open_read_mode_not_flagged(self):
        """Path("x").open("r") ist Read, kein non-atomar-Risiko."""
        src = (
            'from pathlib import Path\n'
            'Path("foo.txt").open("r").read()\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(f, [])

    def test_pathlib_open_no_args_not_flagged(self):
        """Path("x").open() ohne Args ist Read-Default."""
        src = (
            'from pathlib import Path\n'
            'Path("foo.txt").open().read()\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(f, [])

    def test_pathlib_write_text(self):
        src = (
            'from pathlib import Path\n'
            'Path("foo.txt").write_text("hello")\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0][1], "foo.txt")
        self.assertEqual(f[0][2], "w")

    def test_pathlib_write_bytes(self):
        src = (
            'from pathlib import Path\n'
            'Path("foo.bin").write_bytes(b"hello")\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0][1], "foo.bin")
        self.assertEqual(f[0][2], "wb")

    def test_pathlib_via_module_const(self):
        """OUT_PATH = "out.txt"; Path(OUT_PATH).write_text(...) – Pfad aus
        Modul-Konstante aufgeloest."""
        src = (
            'from pathlib import Path\n'
            'OUT_PATH = "out.txt"\n'
            'Path(OUT_PATH).write_text("x")\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0][1], "out.txt")

    def test_allow_marker_works_for_pathlib(self):
        src = (
            'from pathlib import Path\n'
            'Path("foo.txt").write_text("x")  # allow-nonatomic: append-log\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(f, [])

    def test_unrelated_methods_not_flagged(self):
        """Nicht jeder .open() ist pathlib – z.B. file_handle.open() einer
        Custom-API. Wenn der Mode aber 'w'/'a' ist, ist die Heuristik
        bewusst broad: lieber falsch-positiv (kann mit Marker freigeschaltet
        werden) als falsch-negativ. Aber: andere Methodennamen wie .save(),
        .commit() bleiben unberuehrt."""
        src = (
            'obj.save("foo.txt")\n'
            'obj.commit()\n'
            'obj.flush()\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(f, [])

    def test_os_fdopen_not_flagged(self):
        """os.fdopen wird in den atomaren Helfern selbst genutzt – darf
        nicht versehentlich gemeldet werden."""
        src = (
            'import os\n'
            'fd = 0\n'
            'os.fdopen(fd, "w").write("x")\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        # os.fdopen ist Attribute-Call mit attr="fdopen" – nicht in unserer
        # {open, write_text, write_bytes}-Whitelist.
        self.assertEqual(f, [])


class TestModeBypassRegression(unittest.TestCase):
    """FIX BUG-MODE-DYN: Vorher rutschte open(path, mode) mit Variable-Mode
    durch den Check, weil nur _ast.Constant akzeptiert wurde. Jetzt loest
    der Check Modul-Level-Konstanten auf."""

    def test_dynamic_mode_via_module_const_detected(self):
        src = (
            'WRITE_MODE = "w"\n'
            'open("foo.txt", WRITE_MODE)\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(len(f), 1, f"Erwartet 1 Finding, bekam {f}")
        self.assertEqual(f[0][1], "foo.txt")
        self.assertEqual(f[0][2], "w")

    def test_dynamic_mode_via_kwarg_detected(self):
        src = (
            'M = "a"\n'
            'open("foo.txt", mode=M)\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0][2], "a")

    def test_dynamic_mode_pathlib_open_detected(self):
        src = (
            'from pathlib import Path\n'
            'M = "w"\n'
            'Path("foo.txt").open(M)\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0][2], "w")

    def test_truly_dynamic_mode_not_flagged(self):
        """Wenn der Mode aus einer wirklich nicht-statischen Quelle kommt
        (Funktions-Argument, env, Berechnung), ist der Check still – das
        ist gewollt: keine False-Positives bei legitimen Wrappern.

        Nur Modul-Level-Konstanten werden aufgeloest."""
        src = (
            'def f(mode):\n'
            '    open("foo.txt", mode)\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(f, [])

    def test_constant_read_mode_via_var_not_flagged(self):
        """Variable-Mode mit Read-Mode wird KORREKT nicht gemeldet."""
        src = (
            'M = "r"\n'
            'open("foo.txt", M)\n'
        )
        f = _find_non_atomic_writes_in_src(src)
        self.assertEqual(f, [])


class TestHeredocRegexRegression(unittest.TestCase):
    """FIX BUG-HEREDOC-INTERP: Die Heredoc-Erkennung muss neben 'python3 << EOF'
    auch 'python3.11', 'python', '<<-' und '-u/-B'-Flags akzeptieren – sonst
    wird Workflow-inline-Python in diesen Varianten vom Hygiene-Check
    komplett uebersprungen."""

    HEREDOC_RE_SRC = (
        r"\bpython3?(?:\.\d+)?(?:\s+-\w+)*\s*<<-?\s*['\"]?(\w+)['\"]?\s*$"
    )

    def _matches(self, line):
        import re
        return bool(re.search(self.HEREDOC_RE_SRC, line, re.MULTILINE))

    def test_plain_python3_heredoc(self):
        self.assertTrue(self._matches("python3 << EOF"))

    def test_python3_with_flags(self):
        self.assertTrue(self._matches("python3 -u << EOF"))
        self.assertTrue(self._matches("python3 -u -B << EOF"))

    def test_python_with_minor_version(self):
        self.assertTrue(self._matches("python3.11 << EOF"))
        self.assertTrue(self._matches("python3.12 << PYEOF"))

    def test_python_without_major_suffix(self):
        self.assertTrue(self._matches("python << EOF"))

    def test_indent_strip_heredoc(self):
        self.assertTrue(self._matches("python3 <<- EOF"))

    def test_quoted_delimiter(self):
        self.assertTrue(self._matches("python3 << 'EOF'"))
        self.assertTrue(self._matches('python3 << "EOF"'))

    def test_python_c_oneliner_not_heredoc(self):
        self.assertFalse(self._matches("python3 -c 'foo'"))

    def test_pythonsomething_not_match(self):
        """'pythonic' oder 'pythonista' soll nicht wie 'python' aussehen."""
        # \b stellt sicher, dass nach 'python3?(\.\d+)?' kein Word-Char folgt
        # (da darauf \s+ oder \s*<< kommen muss).
        self.assertFalse(self._matches("pythonista << EOF"))
        self.assertFalse(self._matches("pythonic stuff << EOF"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
