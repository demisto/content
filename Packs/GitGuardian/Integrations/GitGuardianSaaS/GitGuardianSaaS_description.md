Use this integration to collect secret incidents and audit logs from the GitGuardian SaaS platform.
You can also use the ***gitguardian-saas-get-events*** command to manually collect events.

## Server URL

- US region: `https://api.gitguardian.com`
- EU region: `https://api.eu1.gitguardian.com`

For GitGuardian Enterprise (`enterprise.gitguardian.com`), use the **GitGuardian Enterprise** integration instead.

## API Key

GitGuardian offers two API key types: a **Service Account** (recommended, a non-human token for automation) and a **Personal Access Token**.

1. In the GitGuardian dashboard, create a Service Account (or a Personal Access Token).
2. Grant the scopes `incidents:read` and `audit_logs:read`.
3. Copy the token value and use it as the **API Key** parameter.

**Note:** For a Personal Access Token, the `audit_logs:read` scope is only available to workspace Managers. A Service Account avoids this constraint.

For more information, see the [GitGuardian authentication documentation](https://docs.gitguardian.com/api-docs/authentication).
