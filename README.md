# adguard-parental-alerts

Dev tier: 3 (public)

**Get a phone alert the moment AdGuard Home blocks adult content on your network.**

AdGuard Home already blocks the sites. What it does not do is tell you, right then, that
somebody tried. This is a small container that watches the AdGuard query log and sends a
[Pushover](https://pushover.net) notification the moment a parental or adult-content block
happens, naming the domain and which device asked for it.

- **One container, no database.** Polls the AdGuard API, remembers what it has already
  alerted on in memory, and nothing else.
- **Tells you which device.** Uses AdGuard's own client names, so the alert says "Kids iPad"
  rather than an IP address.
- **High-priority by default.** Alerts go out with Pushover priority 1 and the siren sound,
  because the whole point is that you see it now.
- **Starts loud.** Sends a "Monitor Started" notification on boot, so you know it is alive
  rather than quietly dead.

## Install

```sh
git clone https://github.com/markhaines/adguard-parental-alerts
cd adguard-parental-alerts
cp .env.example .env
$EDITOR .env          # AdGuard URL + credentials, Pushover token + user key
docker compose up -d
```

That is the whole install. `docker compose logs -f` to watch it.

## Configuration

Every setting is an environment variable, all of them in `.env`:

| Variable | Required | Default | What it is |
|---|---|---|---|
| `ADGUARD_URL` | yes | | Base URL of AdGuard Home, e.g. `https://adguard.example.com` |
| `ADGUARD_USERNAME` | yes | | AdGuard admin username |
| `ADGUARD_PASSWORD` | yes | | AdGuard admin password |
| `PUSHOVER_TOKEN` | yes | | Pushover application token |
| `PUSHOVER_USER` | yes | | Pushover user key |
| `POLL_INTERVAL` | no | `60` | Seconds between query-log polls |

The container exits immediately with a clear message if any required variable is missing.

## What counts as a block worth alerting on

A query-log entry triggers an alert if any of these hold:

- its `reason` contains `parental`, `adult`, `safebrowsing` or `filteredparental`
- a matched filter rule's text contains `porn`, `adult`, `xxx`, `sex` or `nsfw`
- a matched rule comes from filter list `1000001` (AdGuard's adult-content list)

## Known limitations

Both of these are pinned by tests in `tests/test_monitor.py`, so they are current
behaviour rather than accidents. Neither is fixed, because changing either one is a
detection-policy decision.

- **`sex` is matched as a bare substring**, so a rule mentioning `essex.ac.uk`,
  `sussex.ac.uk` or `middlesexhospital.org` raises an adult-content alert. On a tool that
  tells a parent their child looked at adult content, a false positive is the expensive
  direction. Tightening it to require a token boundary would fix those but would also stop
  matching things like `freeporn.com`, so it is a trade-off, not a typo.
- **SafeBrowsing blocks are reported as adult content.** `safebrowsing` is in the reason
  list, but AdGuard's SafeBrowsing blocks malware and phishing. Such a block arrives under
  the title "Adult Content Blocked". The notification body does carry the real reason.

A third thing worth knowing: if AdGuard becomes unreachable, the poller logs the error and
keeps going. Alerts stop, but nothing tells you they have stopped. Treat this as a nice-to-have
alerting path, not a guarantee.

## Development

```sh
pip install -r requirements-dev.txt
pytest -q          # tests
ruff check .       # lint
mypy .             # typecheck
```

CI runs all three on every push and pull request.

## Releases

Semver, tagged `vMAJOR.MINOR.PATCH`. Behaviour changes to what counts as a block are
breaking changes for anyone relying on the alerts, so they get a major bump. See
[CHANGELOG.md](CHANGELOG.md).

## Licence

[MIT](LICENSE).
