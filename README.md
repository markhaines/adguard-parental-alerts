# AdGuard Home parental alerts

This container polls the AdGuard Home query log and sends a Pushover notification when AdGuard reports a parental-content block.

## Configuration

Copy `.env.example` to `.env` and configure these variables:

- `ADGUARD_URL` (required): the AdGuard Home base URL, such as `https://192.168.1.2:3000`.
- `ADGUARD_USERNAME` (required): an AdGuard Home account with query-log access.
- `ADGUARD_PASSWORD` (required): the password for that account.
- `PUSHOVER_TOKEN` (required): the Pushover application's API token.
- `PUSHOVER_USER` (required): the Pushover user or group key that receives alerts.
- `POLL_INTERVAL` (optional): seconds between query-log polls. The default is `60`.
- `ADULT_FILTER_IDS` (optional): comma-separated integer filter-list IDs, such as `42,43`. Whitespace and duplicate IDs are accepted. When unset or empty, only AdGuard's native `FilteredParental` events generate alerts.

> **Subscribed adult blocklists require configuration.** AdGuard Home reports blocks from subscribed adult blocklists as `FilteredBlackList`, not `FilteredParental`. If you rely on a subscribed adult blocklist instead of AdGuard's native Parental Control, you **must** add that list's numeric ID to `ADULT_FILTER_IDS` or those blocks will not generate alerts. This setting does not make every `FilteredBlackList` event parental; only rules belonging to the listed IDs are included.

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
