## Databricks Integration for Cortex XSIAM

### Prerequisites
- A Databricks workspace with a valid URL (e.g., `https://dbc-xxxxx.cloud.databricks.com`)
- A Personal Access Token (PAT) with appropriate permissions

### How to Generate a Personal Access Token
1. Log in to your Databricks workspace
2. Click your username in the top-right corner and select **Settings**
3. Go to **Developer** > **Access tokens**
4. Click **Manage** > **Generate new token**
5. Enter a description and optional lifetime, then click **Generate**
6. Copy the token immediately — it will not be shown again

### Configuration
- **Databricks Workspace URL**: Your workspace URL (e.g., `https://dbc-xxxxx.cloud.databricks.com`)
- **Personal Access Token**: The PAT generated above
- **Fetch incidents**: Enable to pull SQL alerts and failed job runs as incidents

### Troubleshooting

**"Test failed" when configuring the integration:**
- Verify the Workspace URL is correct (no trailing slash, includes `https://`)
- Ensure the Personal Access Token is valid and has not expired
- Check that the token has permission to access SQL Warehouses (used for connectivity test)

**"403 Forbidden" errors on specific commands:**
- Some APIs require admin-level permissions. Verify your token's user has the required role
- Databricks Free Edition does not support all APIs (e.g., SCIM, cluster creation). Commands targeting unsupported features will return 403

**Fetch incidents returns no results:**
- Confirm "Fetch types" is set to at least one of: SQL Alerts, Failed Jobs
- Check "First fetch time" — a very short window may miss older events
- For SQL Alerts, verify alerts exist and have been triggered in your workspace

**Timeout errors on large queries:**
- SQL Statement Execute may time out for long-running queries. Use `databricks-sql-statement-get-status` to poll for results
- Increase the HTTP timeout in the integration instance advanced settings if needed
