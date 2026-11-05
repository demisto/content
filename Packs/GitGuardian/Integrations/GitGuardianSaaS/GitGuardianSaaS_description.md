## GitGuardian SaaS

Use this integration to collect secret incidents and audit logs from the GitGuardian SaaS platform.

### Server URL

- US region: `https://api.gitguardian.com`
- EU region: `https://api.eu1.gitguardian.com`

For GitGuardian Enterprise (`enterprise.gitguardian.com`), use the **GitGuardian Enterprise** integration instead.

### API Key

GitGuardian offers two API key types: a **Service Account** (recommended, a non-human token for automation) and a **Personal Access Token**. The API key must have the `incidents:read` and `audit_logs:read` scopes.

#### Service Account (recommended)

Only workspace Managers can create service accounts. Service accounts require the Growth or Enterprise plan.

1. In the GitGuardian dashboard, go to the **API** section of your workspace and open the **Service accounts** page.
2. Click **Create service account**.
3. Enter a name and set an expiry date for the token.
4. Select the `incidents:read` and `audit_logs:read` scopes.
5. Click **Create service account**.
6. Copy the token and use it as the **API Key** parameter. The token is shown only once.

#### Personal Access Token

1. In the GitGuardian dashboard, go to the **API** section of your workspace and open the **Personal access tokens** page.
2. Click **Create token**.
3. Enter a name and set an expiry date for the token.
4. Click **Create token**.
5. Copy the token and use it as the **API Key** parameter. The token is shown only once.

**Note:** For a Personal Access Token, the `audit_logs:read` scope is only available to workspace Managers.

For more information, see the [GitGuardian authentication documentation](https://docs.gitguardian.com/api-docs/authentication).
