# adguard-parental-alerts

## Language

- **Block**: An AdGuard Home query-log entry rejected by a parental or adult-content filter. The thing worth alerting on.
- **Client name**: AdGuard's own label for a device ("Kids iPad"). Used in alerts instead of an IP.
- **Seen set**: The in-memory record of already-alerted blocks. Lost on restart, deliberately. See ADR-0001.
- **Monitor Started**: The boot notification, so a silent monitor is distinguishable from a dead one.
