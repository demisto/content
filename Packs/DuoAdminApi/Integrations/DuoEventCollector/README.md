Log collecting from Duo

## Configure Duo Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for Duo Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter**             | **Description**                                                                                  | **Required** |
|---------------------------|--------------------------------------------------------------------------------------------------|--------------|
| Server Host               | Duo api host (api-XXXXXXXX.duosecurity.com)                                                      | True         |
| First fetch from api time | The time to fetch from on the first run                                                          | True         |
| Integration key           | API integration key                                                                              | True         |
| Secrete key               | API secrete key                                                                                  | True         |
| XSIAM request limit                    | The number of results to get from the api and to add to XSIAM                                    | True         |
| Request retries                   | We can get `to many request http error` so we will retry the request according to this parameter | False        |


4. Click **Test** to validate the URLs, tokens, and connection.
## Commands
You can execute these commands in a playbook.
#### test-module
***
Integration command for testing.

#### fetch-events
***
Command that is activated by the engine to fetch event.

####$ duo-get-events
***
Manual command to fetch events and display them.