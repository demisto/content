### Authentication

In the Atlassian Standard Connector, pick one of these connection profiles:

- **Username and API token (basic)**: your Atlassian account email address plus a scoped
  API token from https://id.atlassian.com/manage-profile/security/api-tokens (or a
  legacy app password). Bitbucket Cloud deprecated app passwords on June 9, 2026.
- **OAuth 2.0 client credentials**: the Key (Client ID) and Secret (Client Secret) of an
  OAuth consumer created under **Workspace settings** > **Apps and features** >
  **OAuth clients**, with the client-credentials grant enabled. The platform gets the
  token from `https://bitbucket.org/site/oauth2/access_token` and refreshes it.

### Required permissions

Grant the token or OAuth consumer the scopes for the commands you intend to run, e.g.
read/write access to Account, Repositories, Projects, Pull requests and Issues. The
project commands need **Read** permission for **Projects**.

### Workspace

Set **Workspace** to the Bitbucket workspace slug or UUID, and optionally a default
**Repository**.
