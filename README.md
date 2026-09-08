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
| `FAILURE_ALERT_AFTER` | no | `5` | Consecutive failed polls before alerting that the monitor itself is broken |

The container exits immediately with a clear message if any required variable is missing.

## What counts as a block worth alerting on

Entries are classified into one of two categories, each with its own notification
title, because they are not the same thing:

| Category | Title | When |
|---|---|---|
| Adult | `Adult Content Blocked` | AdGuard's parental filter fired, or the rule came from filter list `1000001` (its adult list), or the domain looks adult by keyword |
| Malware | `Malware or Phishing Blocked` | AdGuard SafeBrowsing fired |

The first two adult signals are AdGuard's own judgement and are trusted outright. The
keyword heuristic is the fuzzy one, so it is deliberately strict: a keyword
(`porn`, `adult`, `xxx`, `sex`, `nsfw`) must be **a whole domain label, or start one, or
end one**. `pornhub` and `freeporn` both match; `middlesexhospital` does not.

A short list of innocent labels that would still collide is excluded outright:
the English places ending in `-sex` (Essex, Sussex, Middlesex, Wessex), plus `unisex`,
`sexton`, and the adult-education family. Extend `KEYWORD_EXCEPTIONS` in `monitor.py`
rather than loosening the matcher.

## Known limitations

- **The keyword heuristic is a heuristic.** It matches on label boundaries, not meaning,
  so a genuinely adult domain using none of the five keywords is only caught if AdGuard's
  own parental filter or adult filter list catches it, which they usually do. Erring
  towards missing one is deliberate: on a tool that tells a parent their child looked at
  adult content, a false positive is the expensive direction.
- **De-duplication is in memory only.** Restarting the container can re-alert on entries
  still in AdGuard's query log.

## Development

```sh
pip install -r requirements-dev.txt
pytest -q          # tests
ruff check .       # lint
mypy .             # typecheck
```

CI runs all three on every push and pull request.

## If it stops working

The monitor alerts on its own failure. After `FAILURE_ALERT_AFTER` consecutive failed
polls (default 5, so five minutes at the default interval) it sends **"AdGuard Monitor
Failing"**, saying explicitly that adult-content alerts are not being delivered, and sends
**"AdGuard Monitor Recovered"** when polling resumes. Each fires once per episode rather
than every poll, because a monitor that pages every 60 seconds gets muted, which is the
same as being silent.

## Releases

Semver, tagged `vMAJOR.MINOR.PATCH`. Behaviour changes to what counts as a block are
breaking changes for anyone relying on the alerts, so they get a major bump. See
[CHANGELOG.md](CHANGELOG.md).

## Licence

[MIT](LICENSE).
