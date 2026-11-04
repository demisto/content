## GitBook Sites Event Collector

This integration collects the **organisation site inventory** from GitBook and ingests it into the
Cortex Platform (dataset: `gitbook_sites_raw`).

A site is the public face of documentation. Its visibility and its published state decide whether
internal material is reachable from the internet, which makes the site inventory the public
exposure surface of the organisation. The two settings are not the same thing, so each is a column
of its own: a site can be public in configuration and not yet be published.

The collected record holds the site identifier, title, basename, type and applied type, the visibility and
published state, the creation time, the count of attached site spaces, the application URL, and one
boolean column per site permission.

### What this collector is, and is not

The GitBook API exposes **no audit log**, so there is no record of who changed a site and when.
This is a **snapshot** collector: it re-sends the full inventory on every run, and duplicate rows
across runs are correct, because comparing successive snapshots is the only way a change becomes
visible.

That shapes what can be detected. A site turning public, or a site being published, is found by
comparing snapshots rather than by reading an event, so a detection sees that something is now
different and cannot say who changed it.

### Configuration

| Setting | Value |
| --- | --- |
| GitBook API URL | `https://api.gitbook.com` |
| API token | A personal access token, in the password field |
| Organization ID | From the application URL, `https://app.gitbook.com/o/<organizationId>/` |
| Events Fetch Interval | 60 minutes |

Create the token in GitBook under `User Settings > Developer > Personal access tokens`.

The token owner needs an **administrator role** in the organisation. A site the token owner cannot
see is not returned, so a token with narrower access produces an inventory that understates the
exposure surface rather than an error.

### Permissions

The token carries the permissions of the person who created it, so it can read whatever they can.
Create it under an account that is meant to have organisation-wide visibility, and revoke it in the
same place if that account changes hands.
