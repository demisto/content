## Tessian Event Collector

Use this integration to collect security events from Proofpoint Tessian into Cortex XSIAM.

### Configure Portal URL

Use the hostname of your Proofpoint/Tessian Portal (your tenant subdomain):

- `https://{subdomain}.tessian-platform.com` (EU-hosted)
- `https://{subdomain}.tessian-app.com` (US-hosted)

### Permissions

Ensure the user role has both **Integrations** and **Security Events** permissions before generating the token.

### Generate API Token

1. In the Proofpoint Portal, navigate to **Integrations** → **Security Integrations** → **Proofpoint API**.
2. Select **Create New Token** and copy the API token.

> **Note:** Store the API token securely as it will only be shown upon creation. If you lose access to it, delete it from the Proofpoint Portal and create a new one. If you believe the token has been compromised, delete it immediately and contact your Account Manager.