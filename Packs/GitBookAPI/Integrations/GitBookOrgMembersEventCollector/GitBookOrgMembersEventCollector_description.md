## GitBook Organisation Members Event Collector

This integration collects the **organisation member roster** from GitBook and ingests it into the
Cortex Platform (dataset: `gitbook_members_raw`).

A GitBook member record is the whole access story for one person. It carries the role they hold,
whether they arrived through single sign-on, whether the account is disabled, when they joined and
when they were last seen, and how many spaces, sites and teams they can reach. That makes the
roster the answer to the questions worth asking of a documentation platform: who administers it,
which of those administrators authenticate with a password rather than through the identity
provider, and which privileged accounts nobody is using.

The member email address is collected. It is the identifier that makes a finding actionable, since
a display name is neither unique nor stable, and it is the value needed to tie a GitBook
administrator to an identity elsewhere.

### What this collector is, and is not

The GitBook API exposes **no audit log**, so there is no record of who did what and when. This is a
**snapshot** collector: it re-sends the full roster on every run, and duplicate rows across runs are
correct, because comparing successive snapshots is the only way a change becomes visible.

That shapes what can be detected. A membership change is found by comparing snapshots rather than
by reading an event, so a detection sees that something is now different and cannot say who changed
it.

### Configuration

| Setting | Value |
| --- | --- |
| GitBook API URL | `https://api.gitbook.com` |
| API token | A personal access token, in the password field |
| Organization ID | From the application URL, `https://app.gitbook.com/o/<organizationId>/` |
| Events Fetch Interval | 60 minutes |

Create the token in GitBook under `User Settings > Developer > Personal access tokens`.

The token owner needs an **administrator role** in the organisation. A token belonging to a member
without that role is accepted by the API but cannot read the roster, which surfaces as a permission
error when you click Test.

### Permissions

The token carries the permissions of the person who created it, so it can read whatever they can.
Create it under an account that is meant to have organisation-wide visibility, and revoke it in the
same place if that account changes hands.
