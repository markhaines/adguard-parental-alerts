# Changelog: adguard-parental-alerts

All notable changes to this project. Semver, tagged `vMAJOR.MINOR.PATCH`.

Reconstructed from git history on 2026-09-08.

## Unreleased

### Fixed
- **Innocent domains were reported as adult content.** `sex` and `adult` were matched as
  bare substrings against filter-rule text, so a rule mentioning `essex.ac.uk`,
  `sussex.ac.uk`, `middlesexhospital.org`, `wessexwater.co.uk` or `adulteducation.org`
  raised an "Adult Content Blocked" alert. On a tool that tells a parent their child looked
  at adult content, that is the expensive direction to get wrong.

  Matching is now per domain label, and a keyword must be the whole label, start it, or end
  it. Prefix and suffix both count because real adult domains use both (`pornhub`,
  `freeporn`), while `middlesexhospital` matches neither. `KEYWORD_EXCEPTIONS` covers the
  handful that still collide: the English places ending in `-sex`, plus `unisex`, `sexton`
  and the adult-education family.
- **SafeBrowsing blocks were titled "Adult Content Blocked".** SafeBrowsing blocks malware
  and phishing. Blocks are now classified as `adult` or `safebrowsing`, each with its own
  title, and adult wins if an entry somehow looks like both. Both are still alerted on.
- **De-duplication could re-alert on a domain it had already alerted on.** `seen_entries`
  was a set trimmed with `set(list(seen_entries)[-5000:])`, and a set has no order, so that
  kept an arbitrary 5000 ids rather than the most recent: recent entries could be dropped
  and alerted again while stale ones were kept. It is now an insertion-ordered dict and
  `trim_seen` drops the oldest.
- **The monitor could stop monitoring silently.** A failed poll only wrote to a log nobody
  reads: alerts simply stopped, and nothing said so. After `FAILURE_ALERT_AFTER`
  consecutive failures (default 5) it now sends "AdGuard Monitor Failing", stating that
  adult-content alerts are not being delivered, and "AdGuard Monitor Recovered" when
  polling resumes. Each fires once per episode, not every poll, because a monitor that
  pages every 60 seconds gets muted, which is the same as being silent.
  A non-200 response counts as a failure too; it previously returned early without even
  counting.
- A `filter_list_id` arriving as the string `"1000001"` no longer slips through.

### Added
- 35 tests, up from 13. Every fix above has a test that fails on the previous
  implementation: 34 of the 35 do.
- Lint (`ruff`), typecheck (`mypy`) and the tests, all running in CI on every push and pull
  request.
- A real README (this is a public repo and had a one-line stub), an MIT `LICENSE`, an
  explicit `requirements.txt`, and this changelog. That completes Dev tier 3.
- `FAILURE_ALERT_AFTER` environment variable.

### Changed
- `classify_block(entry)` is the function to use when the category matters.
  `is_parental_block(entry)` is kept as the published name and now means "worth alerting
  on at all".
- `seen_entries` carries its element type; imports are sorted.

## Earlier

### Added
- The monitor: polls the AdGuard Home query log, classifies parental and adult-content
  blocks, and sends a high-priority Pushover notification naming the domain and the client
  device. Ships as a Docker container with a compose file.
