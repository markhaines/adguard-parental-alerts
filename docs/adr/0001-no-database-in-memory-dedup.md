# ADR-0001: No database: remember what has been alerted on in memory

- **Status:** Accepted
- **Date:** 2026-09-18
- **Supersedes:** none

## Context

The container polls the AdGuard query log and alerts on parental or adult-content blocks. It
must not alert twice for the same block, so it has to remember what it has already sent.

The reflex is a small database or a state file on a volume. That adds a volume to the
install, a schema, a migration story, and a failure mode where the state file is corrupt or
unwritable. For something published for other people to run, every one of those is a support
question.

## Decision

**One container, no database.** Poll the AdGuard API, remember what has already been alerted
on **in memory**, and nothing else. Install is `docker compose up -d` with a `.env`, and
that is the whole install.

## Consequences

A restart re-alerts on anything still inside the poll window. That is the right way round
for this tool: the failure mode is one duplicate notification, not a missed one, and the
whole point is that you see it now.

It also means no history, no daily summary and no way to answer "what happened last week"
without going to AdGuard itself, which is where that data already lives.

## Options rejected

- **SQLite on a volume.** A volume, a schema and a corruption path, to prevent a duplicate
  notification after a restart.
- **Persist to a plain state file.** Same support surface, fewer guarantees.
