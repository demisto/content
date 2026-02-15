Gitlab Events Collector
-
Collects the events log for audit events provided by Gitlab API.

## Prerequisites

To retrieve audit events using the API, you must authenticate yourself as an Administrator.

You must use [Personal access tokens](https://docs.gitlab.com/user/profile/personal_access_tokens.html):

### Create a personal access token:

1. In the upper-right corner, select your avatar.
2. Select **Edit profile**.
3. On the left sidebar, select **Personal access tokens**.
4. Select **Add new token**.
5. In **Token name**, enter a name for the token.
6. Optional. In **Token description**, enter a description for the token.
7. In **Expiration date**, enter an expiration date for the token.
   - The token expires on that date at midnight UTC. A token with the expiration date of 2024-01-01 expires at 00:00:00 UTC on 2024-01-01.
   - If you do not enter an expiry date, the expiry date is automatically set to 365 days later than the current date.
   - By default, this date can be a maximum of 365 days later than the current date. In GitLab 17.6 or later, you can extend this limit to 400 days.
8. Select the desired scopes (see [PAT scopes](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html)).
9. Select **Create personal access token**.

---

## Configuration Parameters

* **Server URL** - The API domain URL for Gitlab.
* **API key** - The personal access token created above with administrator authorization.
* **Fetch Instance Audit Events** - Whether to fetch instance audit events. This type of fetch requires your token to have administrator authorization. See [Audit Events API documentation](https://docs.gitlab.com/api/audit_events/).
* **Groups IDs** - A comma-separated list of group IDs.
* **Projects IDs** - A comma-separated list of project IDs.
* **First fetch from API time** - The time to first fetch from the API.
* **The maximum number of events to fetch for each event type** - Each fetch will bring the `limit` number of events for each event type (audits, groups and projects) and each group/project ID. For example, if `limit` is set to 500 and groups/projects IDs are given as well, then the fetch will bring 500 audit events and 500 group/project events for each group/project ID.
