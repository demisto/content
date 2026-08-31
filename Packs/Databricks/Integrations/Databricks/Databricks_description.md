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
