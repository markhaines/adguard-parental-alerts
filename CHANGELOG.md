# Changelog: adguard-parental-alerts

All notable changes to this project. Semver, tagged `vMAJOR.MINOR.PATCH`.

Reconstructed from git history on 2026-09-08.

## Unreleased

### Added
- 13 tests over `is_parental_block`, covering both directions: a miss means the alert never
  arrives, a false positive means a parent is told something untrue about their child.
- Lint (`ruff`), typecheck (`mypy`) and the tests, all running in CI on every push and pull
  request.
- A real README (this is a public repo and had a one-line stub), an MIT `LICENSE`, an
  explicit `requirements.txt`, and this changelog. That completes Dev tier 3.
- A "Known limitations" section in the README, and tests pinning both of the behaviours it
  describes so neither can change by accident:
  - `sex` is matched as a bare substring, so `essex.ac.uk`, `sussex.ac.uk` and
    `middlesexhospital.org` all raise an adult-content alert.
  - SafeBrowsing blocks (malware and phishing) are alerted under the title "Adult Content
    Blocked".

  Neither is fixed here. Both are detection-policy decisions rather than tidy-ups:
  tightening the keyword match to a token boundary would clear the universities but would
  also stop matching `freeporn.com`.

### Changed
- `seen_entries` carries its element type; imports are sorted. No behaviour change.

## Earlier

### Added
- The monitor: polls the AdGuard Home query log, classifies parental and adult-content
  blocks, and sends a high-priority Pushover notification naming the domain and the client
  device. Ships as a Docker container with a compose file.
