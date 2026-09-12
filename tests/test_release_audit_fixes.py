"""Regression tests for the release audit; execute the actual workflow Python.

All HTTP and socket traffic is mocked. All outputs use temporary directories.
Run: python3 -m unittest discover -s tests -v
"""
import contextlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import netshield_common as nc
from check_release_lists import check_file, main as release_gate


def workflow_blocks(name):
    if name == "update_confidence_blacklist.yml":
        return [(ROOT / "scripts/build_confidence.py").read_text(encoding="utf-8")]
    lines = (ROOT / ".github/workflows" / name).read_text().splitlines()
    result = []
    i = 0
    while i < len(lines):
        match = re.search(r"\bpython[23]?(?:\s+[^<]*)?\s*<<-?\s*['\"]?([A-Za-z_][A-Za-z_0-9]*)", lines[i])
        if not match or lines[i].lstrip().startswith("#"):
            i += 1
            continue
        start = i + 1
        i = start
        while i < len(lines) and lines[i].strip() != match[1]:
            i += 1
        if i == len(lines):
            raise AssertionError("Missing heredoc delimiter")
        indent = len(lines[i]) - len(lines[i].lstrip())
        result.append("\n".join(line[indent:] for line in lines[start:i]) + "\n")
        i += 1
    return result


def workflow_code(name, marker):
    matches = [code for code in workflow_blocks(name) if marker in code]
    if len(matches) != 1:
        raise AssertionError((name, marker, len(matches)))
    return matches[0]


def public_ips(count):
    start = int(ipaddress.IPv4Address("45.1.0.1"))
    return [str(ipaddress.IPv4Address(start + i)) for i in range(count)]


class Response(io.BytesIO):
    status = 200
    headers = {"honeydb-qpm-remaining": "999"}


class AuditFixTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        old = Path.cwd()
        self.addCleanup(os.chdir, old)
        os.chdir(self.path)
        for folder in (".github/workflows", "state", "reports"):
            Path(folder).mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / ".github/workflows/whitelist.json", ".github/workflows/whitelist.json")
        nc.load_whitelist()
        nc.load_fp_set()
        self.addCleanup(nc.load_fp_set, str(self.path / "missing-fp.json"))

    def fp(self, entries):
        Path("state/false_positives_set.json").write_text(json.dumps({"ips": entries}))
        nc.load_fp_set()

    def run_code(self, name, marker, env=None):
        namespace = {"__name__": "__main__"}
        error = None
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), \
             patch.dict(os.environ, env or {}), \
             patch("socket.create_connection", side_effect=AssertionError("Unexpected live network")), \
             patch("os._exit", side_effect=sys.exit):
            try:
                exec(compile(workflow_code(name, marker), name, "exec"), namespace)
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    error = exc
            except Exception as exc:
                error = exc
        if namespace.get("_mem_watch_stop"):
            namespace["_mem_watch_stop"].set()
        if namespace.get("db") is not None and hasattr(namespace["db"], "close"):
            namespace["db"].close()
        return namespace, error, output.getvalue()

    def assert_run_ok(self, result):
        self.assertIsNone(result[1], result[2][-5000:])

    def rows(self, filename):
        return {line for line in Path(filename).read_text().splitlines() if line and not line.startswith("#")}

    def test_broad_cidrs_rejected_in_both_parser_modes(self):
        for protected in (False, True):
            for prefix in (0, 8, 9, 24, 31):
                with self.subTest(protected=protected, prefix=prefix):
                    self.assertEqual(nc.parse_entries(f"45.1.0.0/{prefix}", protected), set())
            self.assertEqual(nc.parse_entries("45.1.0.1/32", protected), {"45.1.0.1/32"})
        self.assertEqual(nc.parse_entries("8.8.8.8/32", True), set())

    def test_fp_canonical_hosts_and_ranges(self):
        self.fp([" 45.1.0.1 ", "45.1.0.1/32", "45.1.0.2/32", "45.2.0.0/24", "bad", "::1", None])
        self.assertEqual(nc._fp_ips, {"45.1.0.1", "45.1.0.2"})
        for value in ("45.1.0.1", "45.1.0.1/32", "45.1.0.2", "45.1.0.2/32", "45.2.0.9"):
            self.assertTrue(nc.is_in_fp_set(value), value)
        for value in ("bad", "::1", "45.1.0.1/garbage", None, []):
            self.assertFalse(nc.is_in_fp_set(value), value)

    def test_corrupt_fp_aborts_and_preserves_all_indexes(self):
        for content in ("{broken", "[]", '{}', '{"ips":"45.1.0.1"}'):
            with self.subTest(content=content):
                self.fp(["45.1.0.1", "45.2.0.0/24"])
                Path("state/false_positives_set.json").write_text(content)
                with self.assertRaises(ValueError):
                    nc.load_fp_set()
                self.assertTrue(nc.is_in_fp_set("45.1.0.1/32"))
                self.assertTrue(nc.is_in_fp_set("45.2.0.8"))

    def test_unreadable_fp_aborts_and_preserves_previous_state(self):
        self.fp(["45.1.0.1"])
        with patch("builtins.open", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                nc.load_fp_set()
        self.assertTrue(nc.is_in_fp_set("45.1.0.1"))

    def test_empty_fp_state_is_valid(self):
        self.fp([])
        self.assertFalse(nc.is_in_fp_set("45.1.0.1"))

    def test_cve_pipeline_filters_ranges_and_corrupt_fp_preserves_output(self):
        ips = public_ips(1200)
        self.fp([ips[0]])
        body = "\n".join(ips + ["45.3.0.0/24", "1.1.1.1", "100.64.0.1"])
        with patch.object(nc, "fetch_url", return_value=body):
            result = self.run_code("cve_to_ip_mapper.yml", 'SOURCES =')
        self.assert_run_ok(result)
        self.assertEqual(self.rows("cve_exploit_ips.txt"), set(ips[1:]))
        before = Path("cve_exploit_ips.txt").read_bytes()
        Path("state/false_positives_set.json").write_text("{broken")
        with patch.object(nc, "fetch_url", return_value=body):
            result = self.run_code("cve_to_ip_mapper.yml", 'SOURCES =')
        self.assertIsInstance(result[1], ValueError)
        self.assertEqual(before, Path("cve_exploit_ips.txt").read_bytes())

    def test_abuseipdb_direct_output_filters_whitelist_and_fp(self):
        ips = public_ips(800)
        self.fp([ips[0]])
        body = "\n".join(ips + ["1.1.1.1", "8.8.8.8", "100.64.0.1", "45.3.0.0/24"])
        with patch.object(nc, "safe_urlopen", side_effect=lambda *a, **k: Response(body.encode())):
            result = self.run_code("update_combined_blacklist.yml", "MIN_SCORE =", {"ABUSEIPDB_API_KEY_1": "DUMMY_TEST"})
        self.assert_run_ok(result)
        self.assertEqual(self.rows("reputation_blacklist.txt"), set(ips[1:]))

    def test_honey_partial_failures_preserve_list_and_freshness(self):
        ips = public_ips(800)
        env = {"HONEYDB_API_ID": "DUMMY", "HONEYDB_API_KEY": "DUMMY", "GITHUB_EVENT_NAME": "schedule", "FORCE_LIGHT": "false"}
        def api(url, **kwargs):
            body = [{"remote_host": ip} for ip in ips] if url.endswith("/bad-hosts") else []
            return Response(json.dumps(body).encode())
        with patch.object(nc, "safe_urlopen", side_effect=api), patch("time.sleep"):
            self.assert_run_ok(self.run_code("honigtopf.yml", "def api_get(", env))
        before = {p: Path(p).read_bytes() for p in ("honigtopf_ips.txt", "state/honigtopf_freshness.json")}
        for endpoint in ("/bad-hosts", "/services", "/bad-hosts/SSH"):
            for failure in (429, 503, "timeout", "json", "schema", "schema-items"):
                with self.subTest(endpoint=endpoint, failure=failure):
                    def partial(url, **kwargs):
                        if url.endswith(endpoint):
                            if type(failure) is int:
                                raise urllib.error.HTTPError(url, failure, "test", {}, None)
                            if failure == "timeout":
                                raise TimeoutError("test")
                            if failure == "schema-items":
                                return Response(b'[{"error":"test"}]')
                            return Response(b"{broken" if failure == "json" else b'{"error":"test"}')
                        body = [{"remote_host": ip} for ip in ips[:600]] if url.endswith("/bad-hosts") else []
                        return Response(json.dumps(body).encode())
                    with patch.object(nc, "safe_urlopen", side_effect=partial), patch("time.sleep"):
                        result = self.run_code("honigtopf.yml", "def api_get(", env)
                    self.assertIsNotNone(result[1], result[2][-1000:])
                    for path, content in before.items():
                        self.assertEqual(Path(path).read_bytes(), content, path)
        # A complete successful sweep is allowed to remove genuinely absent IPs.
        ips = ips[:600]
        with patch.object(nc, "safe_urlopen", side_effect=api), patch("time.sleep"):
            self.assert_run_ok(self.run_code("honigtopf.yml", "def api_get(", env))
        self.assertEqual(self.rows("honigtopf_ips.txt"), set(ips))

    def test_confidence_rejects_invalid_upstream_state_keys(self):
        ips = public_ips(1200)
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        bad = ["100.64.0.1", "10.0.0.1", "garbage", "::1", "45.3.0.0/24", "045.1.0.1"]
        entry = {"first": day, "last": day, "hq": True, "feeds": ["a", "b"], "today_count": 2, "days_seen": 14}
        Path("seen_db.json").write_text(json.dumps({ip: entry for ip in ips + bad}))
        Path("combined_threat_blacklist_ipv4.txt").write_text("\n".join(ips + bad))
        Path("state/seen_db_meta.json").write_text(json.dumps({"updated": now.strftime("%Y-%m-%d %H:%M UTC")}))
        result = self.run_code("update_confidence_blacklist.yml", "combined_ips = set()", {"NETSHIELD_SQLITE_TEST": "0"})
        self.assert_run_ok(result)
        self.assertEqual(self.rows("blacklist_confidence40_ipv4.txt"), set(ips))

    def test_combined_filters_invalid_state_keys_and_is_repeatable(self):
        ips = public_ips(1500)
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        bad = ["garbage", "::1", "45.1.0.1junk", "045.1.0.1", "45.3.0.0/24", "100.64.0.1"]
        entry = {"first": day, "last": day, "hq": True, "feeds": ["a", "b"], "hq_feed_names": ["cinsscore"], "hq_feeds": 1, "today_count": 2, "days_seen": 14}
        Path("seen_db.json").write_text(json.dumps({ip: entry for ip in ips + bad}))
        Path("state/auto_discovered_feeds.json").write_text('{"feeds":[]}')
        self.fp([ips[0]])
        feed = "\n".join(ips + ["1.1.1.1", "100.64.0.1"])
        snapshots = []
        for repeat in range(2):
            with patch.object(nc, "fetch_url", return_value=feed), patch.object(nc, "resolve_github_moved_url", return_value=None):
                result = self.run_code("update_combined_blacklist.yml", "def _fast_is_protected(", {"NETSHIELD_FEED_WORKERS": "8"})
            self.assert_run_ok(result)
            self.assertEqual(set(result[0]["sorted_ips"]), set(ips[1:]))
            self.assertTrue(set(result[0]["active_ips"]).isdisjoint(bad))
            snapshots.append(json.loads(Path("seen_db.json").read_text()))
        self.assertEqual(snapshots[0], snapshots[1])

    def test_release_gate_rejects_invalid_entries(self):
        path = Path("test.txt")
        path.write_text("# fixture\n45.1.0.1\n45.1.0.2/32\n100.81.245.29\n45.1.0.0/24\n::1\nbad\n")
        entries, rejected, samples = check_file(path)
        self.assertEqual((entries, rejected), (6, 4))
        self.assertEqual(len(samples), 4)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release_gate([str(path)]), 1)
            self.assertEqual(release_gate(["missing.txt"]), 1)
        path.write_text("45.1.0.1\n45.1.0.2/32\n")
        self.assertEqual(check_file(path)[:2], (2, 0))

    def test_all_combined_publications_require_success_and_explicit_approval(self):
        import yaml
        doc = yaml.safe_load((ROOT / ".github/workflows/update_combined_blacklist.yml").read_text())
        names = {"Commit and Push", "Save seen_db JSON Compatibility Cache", "Save seen_db SQLite Cache", "Prepare and verify immutable state generation"}
        checked = set()
        for step in doc["jobs"]["update"]["steps"]:
            if step.get("name") not in names:
                continue
            condition = step["if"]
            self.assertIn("steps.build_combined.outcome == 'success'", condition)
            self.assertIn("steps.shrink_guard.outputs.ok == 'true'", condition)
            checked.add(step["name"])
        self.assertEqual(names, checked)

    def test_release_gate_keeps_geographic_cidr_tables_out_of_scope(self):
        Path("all_countries_ipv4.txt").write_text("45.0.0.0/8\n")
        Path("tweetfeed_ips.txt").write_text("45.1.0.1\n")
        output = io.StringIO()
        with patch("check_release_lists.ROOT", self.path), contextlib.redirect_stdout(output):
            self.assertEqual(release_gate([]), 0)
        self.assertIn("tweetfeed_ips.txt", output.getvalue())
        self.assertNotIn("all_countries", output.getvalue())

    def test_fetch_retries_survive_bash_errexit(self):
        text = (ROOT / "scripts/publish_generation.sh").read_text()
        start = text.index('  if ! git fetch origin "${GITHUB_REF_NAME}"; then')
        end = text.index('\n  fi', start) + len('\n  fi')
        block = "\n".join(line[2:] for line in text[start:end].splitlines())
        for failures, expected_status, calls in ((1, 0, 2), (9, 1, 5)):
            script = f'''count=0
git() {{ count=$((count+1)); echo "fetch:$count"; [ "$count" -gt {failures} ]; }}
sleep() {{ :; }}
for attempt in 1 2 3 4 5; do
{block}
echo PUBLISHED
exit 0
done
exit 1
'''
            result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], capture_output=True, text=True, env={**os.environ, "GITHUB_REF_NAME": "main"})
            self.assertEqual(result.returncode, expected_status, result.stdout + result.stderr)
            self.assertEqual(result.stdout.count("fetch:"), calls)
            self.assertEqual("PUBLISHED" in result.stdout, expected_status == 0)


if __name__ == "__main__":
    unittest.main()
