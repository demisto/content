An event collector for Gitlab audit events and events using Gitlab's API.  

[Audit events API documentation](https://docs.gitlab.com/ee/api/audit_events.html)  
[Events API documentation](https://docs.gitlab.com/ee/api/events.html)
## Configure Gitlab Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for Gitlab Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
|-------|-----------|-------|
| Server Host   | Gitlab Git URL. | True     |
| API key  | The request API key.  | True   |
| Groups IDs  | A comma-separated list of group IDs to get. | False   |
| Projects IDs    | A comma-separated list of project IDs to get. | True         |
| First fetch from API time     | The time to first fetch from the API.  | True         |                                           | True         |


4. Click **Test** to validate the URLs, tokens, and connection.
## Commands
You can execute these commands in a playbook.

#### gitlab-get-events
***
Manual command to fetch events and display them.