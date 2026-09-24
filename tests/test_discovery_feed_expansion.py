"""Regression tests for botnet/scanner discovery and scored CSV ingestion."""
import ast
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import netshield_common as common
from netshield_discovery import (
    BOTNET_QUERIES, SCANNER_QUERIES, FEED_NAME_RE,
    external_feed_urls, has_feed_evidence, prioritized_code_queries,
)

def workflow_tree():
    text = (ROOT / '.github/workflows/auto_feed_discovery.yml').read_text(encoding='utf-8')
    # Parse the embedded program without running network calls or state mutations.
    import textwrap
    start = re.search(r"python3?(?:\s+-u)?\s*<<\s*['\"]?(\w+)['\"]?\s*\n", text)
    assert start
    lines = text[start.end():].splitlines()
    stop = next(i for i, line in enumerate(lines) if line.strip() == start.group(1))
    return ast.parse(textwrap.dedent('\n'.join(lines[:stop])))

class DiscoveryExpansionTests(unittest.TestCase):
    def test_scored_csv_passes_content_discovery_with_shared_policy(self):
        tree = workflow_tree()
        wanted = {'THREAT_CONTEXT_RE', 'PLAIN_IP_LINE_RE'}
        nodes = [n for n in tree.body if (
            isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in wanted for t in n.targets)
        ) or (isinstance(n, ast.FunctionDef) and n.name in {'extract_ips', '_content_profile'})]
        scope = dict(re=re, _parse_feed_entries=common.parse_feed_entries,
                     is_valid_public_ipv4=common.is_valid_public_ipv4,
                     IPV4_RE=common.IPV4_RE, CONTENT_SNIFF_MIN_IPS=30)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<content-profile>', 'exec'), scope)
        raw = 'ip,ffraud_score,confirmations,category,type\n' + '\n'.join(
            f'93.184.216.{i},95,3,botnet,' for i in range(1, 41))
        profile = scope['_content_profile'](raw, 'https://example.net/confirmed-abusive.csv')
        self.assertTrue(profile['looks_like_feed'])
        self.assertEqual(profile['unique_ips'], 40)
        self.assertFalse(scope['_content_profile'](raw.replace(',95,', ',50,'))['looks_like_feed'])

    def test_workflow_filename_patterns_accept_real_formats(self):
        scope = dict(re=re, FEED_NAME_RE=FEED_NAME_RE)
        nodes = [n for n in workflow_tree().body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'IP_FILE_PATTERNS' for t in n.targets)]
        self.assertEqual(len(nodes), 2)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<patterns>', 'exec'), scope)
        pattern = scope['IP_FILE_PATTERNS']
        for path in ['high_confidence_unlimited.txt', 'confirmed-abusive.csv',
                     'blocklist_honeypot_ip4_aged_less_than_90days.txt', 'mirai-hosts.txt', 'scanner-feed.csv']:
            self.assertIsNotNone(pattern.search(path), path)
        self.assertIsNone(pattern.search('README.md'))
        self.assertIsNone(pattern.search('scanner.py'))

    def test_each_run_covers_both_focuses_without_more_requests(self):
        base = [f'filename:feed{i}.txt' for i in range(39)]
        observed = set()
        for run in range(40):
            result = prioritized_code_queries(base, run)
            self.assertEqual(len(result), len(base[run % 2::2]))
            self.assertEqual(len(result), len(set(result)))
            self.assertGreaterEqual(len(set(result) & set(BOTNET_QUERIES)), 2)
            self.assertGreaterEqual(len(set(result) & set(SCANNER_QUERIES)), 2)
            observed.update(result)
        self.assertTrue(set(base).issubset(observed))

    def test_external_documented_feed_and_request_bound(self):
        document = '''[High confidence](https://spydisec.com/high_confidence_unlimited.txt)
Threat feed download: https://feeds.example.net/export/data.csv?x=1&amp;y=2
https://feeds.example.net/export/data.csv?x=1&amp;y=2
https://example.net/unrelated.txt
Threat feed https://user:password@example.net/data.csv
Threat feed https://github.com/test/repo/blob/main/scanner-feed.csv
'''
        result = list(external_feed_urls(document, FEED_NAME_RE))
        self.assertEqual(result, ['https://spydisec.com/high_confidence_unlimited.txt',
                                  'https://feeds.example.net/export/data.csv?x=1&y=2'])
        many = '\n'.join(f'Threat feed https://example.net/{i}.txt' for i in range(30))
        self.assertEqual(len(list(external_feed_urls(many, FEED_NAME_RE))), 12)

    def test_generator_is_not_automatically_mistaken_for_scanner_tool(self):
        self.assertTrue(has_feed_evidence({'description': 'Python generator for a scanner IP blocklist'}))
        self.assertFalse(has_feed_evidence({'description': 'Python vulnerability scanner CLI'}))

    def test_external_feed_does_not_use_readme_commit_cache(self):
        func = next(n for n in workflow_tree().body if isinstance(n, ast.FunctionDef)
                    and n.name == '_get_commit_date_for_feed')
        scope = {}
        exec(compile(ast.Module(body=[func], type_ignores=[]), '<external-cache>', 'exec'), scope)
        # No API functions in scope: any attempted commit lookup would fail.
        self.assertIsNone(scope['_get_commit_date_for_feed']({
            'repo': 'owner/feed', 'file': 'high_confidence_unlimited.txt',
            'detected_by': 'external_url', 'external_source_file': 'README.md'}))

class ScoredCSVTests(unittest.TestCase):
    HEADER = 'ip,ffraud_score,confirmations,category,type\n'

    def test_score_categories_and_ipv4_only(self):
        text = '\ufeff# feed\n' + self.HEADER + '''93.184.216.34,90,2,c2,proxy
91.92.93.94,89,5,malware,
91.92.93.95,95,1,botnet,
91.92.93.96,99,3,scanner,
91.92.93.97,101,3,malware,
91.92.93.98,invalid,3,malware,
::ffff:91.92.93.99,95,3,malware,
10.0.0.1,95,3,malware,
91.92.93.100.example.net,95,3,malware,
91.92.93.101/24,95,3,malware,
'''
        self.assertEqual(common.parse_feed_entries(text), {'93.184.216.34'})

    def test_malformed_schema_cannot_bypass_filter(self):
        self.assertEqual(common.parse_feed_entries('ip,ffraud_score\n93.184.216.34,99'), set())
        self.assertEqual(common.parse_feed_entries('ip,score\n93.184.216.34,99',
            source_hint='https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/main/threat-ips/confirmed-abusive.csv'), set())

    def test_protected_check_is_preserved(self):
        text = self.HEADER + '93.184.216.34,95,3,malware,\n'
        with patch.object(common, 'is_protected_entry', return_value=True) as check:
            self.assertEqual(common.parse_feed_entries(text, use_protected_check=True), set())
            check.assert_called_once_with('93.184.216.34')

    def test_other_csv_and_plain_feeds_unchanged(self):
        self.assertEqual(common.parse_feed_entries('ip,category\n93.184.216.34,scanner'), {'93.184.216.34'})
        self.assertEqual(common.parse_feed_entries('93.184.216.34'), {'93.184.216.34'})

if __name__ == '__main__':
    unittest.main()
