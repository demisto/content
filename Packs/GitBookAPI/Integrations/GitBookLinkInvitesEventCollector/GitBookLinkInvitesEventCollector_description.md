## GitBook Link Invites Event Collector

This integration collects the **organisation link invites** from GitBook and ingests them into the
Cortex Platform (dataset: `gitbook_invites_raw`).

A link invite is a standing URL that grants entry to the organisation. Anyone holding it can join,
it names no recipient, and it keeps working until somebody revokes it. That makes it a live access
path rather than a historical record, which is why an inventory of the ones that exist is worth
holding: each row is a door that is currently open, and the role or level it carries decides how
far whoever walks through it can reach.

The API models an invite link as one of three shapes: an invite to the organisation, which carries
a `role`, and an invite to a space or to a collection, which carries a `level` and names its
target. All three are collected, and an `invite_target` column records which shape a row is so a
rule can filter on it directly.

### What this collector is, and is not

The GitBook API exposes **no audit log**, so there is no record of who did what and when. This is a
**snapshot** collector: it re-sends the full inventory on every run, and duplicate rows across runs
are correct, because comparing successive snapshots is the only way a change becomes visible.

That shapes what can be detected. A new invite is found by comparing snapshots rather than by
reading an event, so a detection sees that an invite now exists and cannot say who created it. The
same applies in reverse: an invite that disappears from a snapshot was revoked, but by whom is not
recoverable from this source.

### Configuration

| Setting | Value |
| --- | --- |
| GitBook API URL | `https://api.gitbook.com` |
| API token | A personal access token, in the password field |
| Organization ID | From the application URL, `https://app.gitbook.com/o/<organizationId>/` |
| Events Fetch Interval | 60 minutes |

Create the token in GitBook under `User Settings > Developer > Personal access tokens`.

The token owner needs an **administrator role** in the organisation. A token belonging to a member
without that role is accepted by the API but cannot read the invites, which surfaces as a
permission error when you click Test.

### Permissions

The token carries the permissions of the person who created it, so it can read whatever they can.
Create it under an account that is meant to have organisation-wide visibility, and revoke it in the
same place if that account changes hands.
