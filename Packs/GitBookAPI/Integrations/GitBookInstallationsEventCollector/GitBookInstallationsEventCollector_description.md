## GitBook Integration Installations Event Collector

This integration collects the **integration installation inventory** from GitBook and ingests it
into the Cortex Platform (dataset: `gitbook_installations_raw`).

An installed integration is third-party code with standing access to documentation content. The
inventory answers which third parties are connected, what they are permitted to reach, whether the
publisher is verified, and whether an installation covers every space and site or only a selection.
That is a supply-chain question rather than a user-access one, so the collected record holds the
installation and the integration it installs together.

The scopes an integration holds are collected, and the two that grant reach beyond reading, writing
space content and injecting script into a published site, are also resolved into their own columns
so a rule does not have to parse the scope list.

The integration configuration is **not** collected. It is supplied by the integration and can hold
the credentials the integration authenticates with.

### What this collector is, and is not

The GitBook API exposes **no audit log**, so there is no record of who installed what and when. This
is a **snapshot** collector: it re-sends the full inventory on every run, and duplicate rows across
runs are correct, because comparing successive snapshots is the only way a change becomes visible.

That shapes what can be detected. A new installation, a widened scope or a removed integration is
found by comparing snapshots rather than by reading an event, so a detection sees that something is
now different and cannot say who changed it.

The collected columns are derived from the published GitBook API specification. A field the
specification marks optional may be absent from a record, and the collector treats that as normal
rather than as an error.

### Configuration

| Setting | Value |
| --- | --- |
| GitBook API URL | `https://api.gitbook.com` |
| API token | A personal access token, in the password field |
| Organization ID | From the application URL, `https://app.gitbook.com/o/<organizationId>/` |
| Events Fetch Interval | 60 minutes |

Create the token in GitBook under `User Settings > Developer > Personal access tokens`.

The token owner needs an **administrator role** in the organisation. A token belonging to a member
without that role is accepted by the API but cannot read the inventory, which surfaces as a
permission error when you click Test.

### Permissions

The token carries the permissions of the person who created it, so it can read whatever they can.
Create it under an account that is meant to have organisation-wide visibility, and revoke it in the
same place if that account changes hands.
