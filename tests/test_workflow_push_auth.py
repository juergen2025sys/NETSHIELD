"""Check real workflows and authentication defaults without network calls."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from netshield_workflow_checks import git_push_auth_warnings


class PushAuthTests(unittest.TestCase):
    def workflow(self, settings="", commands="git push"):
        return ("jobs:\n  update:\n    steps:\n"
                "      - uses: actions/checkout@v7\n" + settings
                + "      - run: |\n"
                + "\n".join("          " + line for line in commands.splitlines()))

    def test_default_checkout_credentials_work(self):
        self.assertEqual(git_push_auth_warnings(self.workflow()), [])

    def test_disabled_credentials_without_alternative_warn(self):
        content = self.workflow("        with:\n          persist-credentials: false\n")
        self.assertEqual(len(git_push_auth_warnings(content)), 1)

    def test_token_url_is_an_alternative(self):
        content = self.workflow(
            "        with:\n          persist-credentials: false\n",
            'push_url="https://x-access-token:${TOKEN}@github.com/${REPO}.git"\n'
            'git push "$push_url" HEAD:main')
        self.assertEqual(git_push_auth_warnings(content), [])

    def test_comment_with_token_url_does_not_hide_warning(self):
        content = self.workflow(
            "        with:\n          persist-credentials: false\n",
            '# Example: https://user:token@github.com/repo\ngit push')
        self.assertEqual(len(git_push_auth_warnings(content)), 1)

    def test_credentials_in_another_job_do_not_hide_warning(self):
        content = (self.workflow("        with:\n          persist-credentials: false\n")
                   + "\n  other:\n    steps:\n      - uses: actions/checkout@v7\n")
        self.assertEqual(len(git_push_auth_warnings(content)), 1)

    def test_actual_reported_workflows_do_not_raise_false_alarms(self):
        for name in ("dns_blocklist_finder.yml", "runner_image_watch.yml"):
            with self.subTest(name=name):
                content = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
                self.assertEqual(git_push_auth_warnings(content), [])


if __name__ == "__main__":
    unittest.main()
