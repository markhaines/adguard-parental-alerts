# AdGuard Home parental alerts

This container polls the AdGuard Home query log and sends a Pushover notification when AdGuard reports a parental-content block.

## Configuration

Copy `.env.example` to `.env` and set the AdGuard and Pushover credentials. `ADULT_FILTER_IDS` can contain a comma-separated list of filter-list IDs that should count as adult-content blocks in addition to AdGuard's `FilteredParental` reason.

Start the service with:

```sh
docker compose up -d --build
```

The monitor sends a low-priority startup notification, then polls at the configured interval. Query-log access requires an AdGuard Home account with access to `/control/querylog`.

## Tests

```sh
python -m pip install requests urllib3
python -m unittest -v
```

Tests cover exact AdGuard reason matching, Safe Browsing separation, innocent substring handling, and configured filter-list IDs.
