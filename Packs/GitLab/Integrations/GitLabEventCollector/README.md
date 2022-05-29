An event collector for Gitlab audit events using and events using Gitlab's the api  

[Audit events api documentation](https://docs.gitlab.com/ee/api/audit_events.html)  
[Events api documentation](https://docs.gitlab.com/ee/api/events.html)
## Configure Gitlab Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for Gitlab Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description**                                       | **Required** |
|---------------|-------------------------------------------------------|--------------|
| Server Host   | Gitlab git url                                        | True         |
| API key     | The request API key                                   | True         |
| Event types     | The event types to get as a comma delimitered string  | False         |
| Groups ids     | The groups ids to get as a comma delimitered string   | False         |
| Projects ids     | The Projects ids to get as a comma delimitered string | True         |
| The product name corresponding to the integration that originated the events     | The name of the product to name the dataset after     | False        |
| The vendor name corresponding to the integration that originated the events     | The name of the vendor to name the dataset after      | False        |
| First fetch from API time     | The time to first fetch from the api                                              | True         |


4. Click **Test** to validate the URLs, tokens, and connection.
## Commands
You can execute these commands in a playbook.

####$ gitlab-get-events
***
Manual command to fetch events and display them.