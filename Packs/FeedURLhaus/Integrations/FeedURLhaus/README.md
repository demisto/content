## URLhaus
---

Fetch indicators from URLhaus api.
=======

Fetch indicators from the URLhaus API.


1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for URLhaus Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter**        | **Description**                                                                            | **Required** |
|----------------------|--------------------------------------------------------------------------------------------|--------------|
| Fetches indicators   | Check tofetch indicators                                                                   | True         |
| Indicator Reputation | The type of reputation for the indicator                                                   | True         |
| Feed Source          | The type of data we want to get from the api                                               | True         |
| Traffic Light Protocol Color               | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. | True         |
| Indicator Expiration Method              | The indicator expiration method                                                            | True         |
| Source Reliability             | The reliability of the feed                                                                | True         |
| Feed Fetch Interval    | The time interval to fetch indicators from the api                                         | True         |
| Trust any certificate    | Weather or not to trust any certificate                                                    | True         |
| Use system proxy settings   | If you want to use proxy for the integration                                               | True         |


4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands in a playbook.

### urlhaus-get-indicators
***
Manual command to fetch events and display them.