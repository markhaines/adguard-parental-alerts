# AdGuard Home parental alerts

This container polls the AdGuard Home query log and sends a Pushover notification when AdGuard reports a parental-content block.

## Configuration

Copy `.env.example` to `.env` and configure these variables:

- `ADGUARD_URL` (required): the AdGuard Home base URL, such as `https://192.168.1.2:3000`.
- `ADGUARD_USERNAME` (required): an AdGuard Home account with query-log access.
- `ADGUARD_PASSWORD` (required): the password for that account.
- `PUSHOVER_TOKEN` (required): the Pushover application's API token.
- `PUSHOVER_USER` (required): the Pushover user or group key that receives alerts.
- `POLL_INTERVAL` (optional): an integer number of seconds from `1` to `86400` (24 hours) between query-log polls. The default is `60`.
- `ADULT_FILTER_IDS` (optional): comma-separated non-negative integer filter-list IDs, such as `0,42`. Whitespace and duplicate IDs are accepted. When unset or empty, only AdGuard's native `FilteredParental` events generate alerts.

> **Adult blocklists and custom rules require configuration.** AdGuard Home reports blocks from subscribed adult blocklists as `FilteredBlackList`, not `FilteredParental`. If you rely on a subscribed adult blocklist instead of AdGuard's native Parental Control, you **must** add that list's numeric ID to `ADULT_FILTER_IDS` or those blocks will not generate alerts. AdGuard uses filter-list ID `0` for Custom filtering rules, so set `ADULT_FILTER_IDS=0` if you maintain adult-domain blocks there. Configured IDs match only `FilteredBlackList` blocks; rewrites and allowlist matches do not generate parental alerts.

To find a subscribed list's numeric ID, inspect `rules[].filter_list_id` for one of its blocked queries in the JSON returned by `/control/querylog`, or match the list in `GET /control/filtering/status`. Custom filtering rules always use ID `0`.

Earlier versions treated filter-list ID `1000001` as adult content automatically. That special default has been removed: if you relied on it, add `1000001` to `ADULT_FILTER_IDS` explicitly to retain those alerts.

Malformed `ADULT_FILTER_IDS` or `POLL_INTERVAL` configuration is fail-safe: the monitor refuses to start and logs a clear error instead of running with partial coverage.

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
