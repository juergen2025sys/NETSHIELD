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


if __name__ == "__main__":
    unittest.main(verbosity=2)
