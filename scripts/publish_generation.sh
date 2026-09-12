#!/usr/bin/env bash
# Publish one verified generation; never merge changed inputs into old outputs.
set -euo pipefail
: "${NETSHIELD_BASE_COMMIT:?missing input commit}"
: "${GITHUB_REF_NAME:?missing target branch}"
python3 scripts/netshield_generation.py
git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"
git rm -q --cached --ignore-unmatch combined_threat_blacklist_ipv4.txt blacklist_confidence40_ipv4.txt \
  state/watchlist_expired_history.json state/active_expired_history.json
git rm -q --ignore-unmatch seen_db_meta.json combined_threat_blacklist_report.md
git add active_blacklist_ipv4.txt watchlist_confidence25to39_ipv4.txt \
  reports/combined_threat_blacklist_report.md state/seen_db_meta.json \
  state/watchlist_daily_cap_state.json state/release_state.json state/confidence_generation.json \
  reputation_blacklist.txt
git add -A -- 'combined_threat_blacklist_ipv4_part*.txt' 'blacklist_confidence40_ipv4_part*.txt'
for optional in relocated_feeds.md feed_url_overrides.json; do
  if [ -f "$optional" ]; then git add -- "$optional"; fi
done
while IFS= read -r -d '' file; do
  if [ "$(git cat-file -s ":$file")" -ge 104857600 ]; then
    echo "::error::Staged file exceeds GitHub size limit: $file"
    exit 1
  fi
done < <(git diff --cached --name-only -z --diff-filter=ACMR)
if git diff --cached --quiet; then
  echo 'Generation already committed'
  exit 0
fi
git commit -m "Update complete NETSHIELD generation"
for attempt in 1 2 3 4 5; do
  if ! git fetch origin "${GITHUB_REF_NAME}"; then
    echo "Fetch fehlgeschlagen (Versuch $attempt/5)"
    if [ "$attempt" -eq 5 ]; then exit 1; fi
    sleep $((attempt * 2))
    continue
  fi
  git merge-base --is-ancestor "$NETSHIELD_BASE_COMMIT" "origin/$GITHUB_REF_NAME"
  # Reports and Markdown may advance independently. Any changed data, config,
  # code or generation pointer invalidates this build and requires a retry.
  if ! git diff --quiet "$NETSHIELD_BASE_COMMIT" "origin/$GITHUB_REF_NAME" -- \
      . ':(exclude)reports/**' ':(exclude)logs/**' ':(exclude)*.md'; then
    echo '::error::Build inputs changed on the remote branch; rerun Combined. No generation was published.'
    exit 1
  fi
  # No automatic conflict preference: either the complete commit applies or
  # publication fails. A concurrent push is rejected without force.
  if ! git rebase "origin/$GITHUB_REF_NAME"; then
    git rebase --abort || true
    exit 1
  fi
  python3 scripts/netshield_generation.py
  if git push origin "HEAD:$GITHUB_REF_NAME"; then
    echo 'Complete generation published'
    exit 0
  fi
  sleep $((attempt * 3))
done
echo '::error::Push failed after five attempts; release pointer was not advanced by this run.'
exit 1
