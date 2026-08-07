## GitBook Space Git Sync Event Collector

This integration collects the **git sync configuration of every space** in a GitBook organisation
and ingests it into the Cortex Platform (dataset: `gitbook_git_sync_raw`).

Git sync connects a space to an external repository, so it is both an egress and an ingress path
for content. Content can leave the platform into a repository, and content can be pushed into
published documentation from one. Which spaces are wired to which repository, on which branch and
in which direction, is what this collector exists to answer.

One record is emitted per space, whether or not that space syncs. A space with git sync carries the
repository, the branch and the sync direction alongside `git_sync_configured` true; a space without
it carries `git_sync_configured` false. Reporting both means a space losing its git sync is visible
as a change rather than as a row that quietly stopped appearing.

### How it collects

Git installations have no list endpoint, `/git/installations` accepts POST only, so the per space
route is the only enumerable path:

| Step | Request |
| --- | --- |
| 1 | `GET /v1/orgs/{organizationId}/spaces` |
| 2 | `GET /v1/spaces/{spaceId}/git/info`, once per space |

That means each space costs one further request, which is what the maximum records per fetch
setting bounds.

A space with no git sync configured answers `404` on step 2. That is an answer rather than a
failure, so it becomes a record with `git_sync_configured` false. Any other status is treated as a
failure and surfaces as an error, because a failure quietly turned into a record would read as an
all clear.

### What this collector is, and is not

The GitBook API exposes **no audit log**, so there is no record of who changed a configuration and
when. This is a **snapshot** collector: it re-sends the full inventory on every run, and duplicate
rows across runs are correct, because comparing successive snapshots is the only way a change
becomes visible.

That shapes what can be detected. A newly connected repository, a changed branch or a reversed sync
direction is found by comparing snapshots rather than by reading an event, so a detection sees that
something is now different and cannot say who changed it.

### Configuration

| Setting | Value |
| --- | --- |
| GitBook API URL | `https://api.gitbook.com` |
| API token | A personal access token, in the password field |
| Organization ID | From the application URL, `https://app.gitbook.com/o/<organizationId>/` |
| Events Fetch Interval | 60 minutes |

Create the token in GitBook under `User Settings > Developer > Personal access tokens`.

The token owner needs an **administrator role** in the organisation. A token belonging to a member
without that role is accepted by the API but cannot list the spaces, which surfaces as a permission
error when you click Test.

### Permissions

The token carries the permissions of the person who created it, so it can read whatever they can.
Create it under an account that is meant to have organisation-wide visibility, and revoke it in the
same place if that account changes hands.
