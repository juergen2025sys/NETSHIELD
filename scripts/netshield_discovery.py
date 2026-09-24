"""Bounded discovery hints. Every result still needs the normal feed validation."""
import html
import re
from urllib.parse import unquote, urlsplit

BOTNET_QUERIES = (
    'botnet blocklist extension:txt',
    '"c2" "ip" extension:csv',
    '"mirai" "blocklist" extension:txt',
    '"infected" "ips" extension:txt',
    '"command-and-control" "feed" filename:README.md',
    '"botnet" "feed" filename:README.md',
)
SCANNER_QUERIES = (
    '"scanner" "blocklist" extension:txt',
    '"honeypot" "ip" extension:csv',
    '"scanning" "blocklist" filename:README.md',
    '"masscan" "feed" filename:README.md',
    '"brute_force" "category" extension:csv',
    '"scanner" "threat feed" filename:README.md',
)
FORMAT_QUERIES = (
    'filename:high_confidence_unlimited.txt',
    'filename:confirmed-abusive.csv',
    '"ffraud_score" extension:csv',
    '"honeypot" "blocklist" filename:README.md',
)
FEED_NAME_RE = re.compile(
    r'(?i)(?:high[-_]confidence(?:[-_](?:limited|unlimited))?|'
    r'confirmed[-_](?:abusive|malicious)|'
    r'(?:blocklist|blacklist|honeypot|scanner|scanners|botnet|c2)[-_][a-z0-9_-]+|'
    r'(?:botnet|scanner|scanning|honeypot|c2)[-_](?:feed|ips?|hosts|servers|recent)|'
    r'(?:mirai|mozi|moobot|qbot|qakbot)[-_](?:ips?|hosts|c2|blocklist))'
    r'\.(?:txt|csv|tsv|list|json)(?:\.gz)?$'
)
THREAT_FEED_RE = re.compile(
    r'(?i)\b(?:botnet|scanner|scanning|honeypot|malicious|threat|c2|brute.?force)\b'
)

def prioritized_code_queries(queries, run_number, chunks=2):
    """Reserve two slots per focus plus one format slot, keeping the old budget."""
    unique = list(dict.fromkeys(queries))
    budget = len(unique[run_number % chunks::chunks])
    if not budget:
        return []
    priority = []
    for pool, count in ((BOTNET_QUERIES, 2), (SCANNER_QUERIES, 2), (FORMAT_QUERIES, 1)):
        priority.extend(pool[(run_number * count + i) % len(pool)] for i in range(count))
    priority = list(dict.fromkeys(priority))[:budget]
    background = [q for q in unique if q not in priority]
    slots = budget - len(priority)
    start = (run_number * max(1, slots)) % max(1, len(background))
    return priority + (background[start:] + background[:start])[:slots]

def external_feed_urls(text, filename_pattern, limit=12):
    """Find direct downloads, including neutral links explicitly labelled as feeds.

    This does not fetch URLs. The caller's safe downloader and content/FP gates
    remain mandatory. The limit bounds URL probes per documentation file.
    """
    seen = set()
    for line in text.splitlines():
        for match in re.finditer(r'https?://[^\s\'"<>()\[\]`]+', html.unescape(line)):
            url = match.group().rstrip('.,;:')
            if url in seen:
                continue
            try:
                parts = urlsplit(url)
                path = unquote(parts.path)
                filename = path.rsplit('/', 1)[-1]
                if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
                    continue
                # A GitHub HTML file page is not a machine-readable feed.
                if parts.hostname.lower() == 'github.com' and '/blob/' in path:
                    continue
            except ValueError:
                continue
            named = filename_pattern.search(filename) or FEED_NAME_RE.search(filename)
            labelled = (THREAT_FEED_RE.search(line)
                        and re.search(r'(?i)\b(?:feed|blocklist|download|ips?)\b', line)
                        and re.search(r'(?i)\.(?:txt|csv|tsv|list|json)(?:\.gz)?$', filename))
            if not (named or labelled):
                continue
            seen.add(url)
            yield url
            if len(seen) >= limit:
                return

def has_feed_evidence(meta):
    """A scanner feed can contain generator code without being a scanner tool."""
    text = ' '.join([meta.get('description') or '', ' '.join(meta.get('topics') or [])])
    return bool(THREAT_FEED_RE.search(text) and re.search(
        r'(?i)\b(?:blocklist|blacklist|ip[- ]feed|threat[- ]feed|ioc[- ]feed)\b', text))
