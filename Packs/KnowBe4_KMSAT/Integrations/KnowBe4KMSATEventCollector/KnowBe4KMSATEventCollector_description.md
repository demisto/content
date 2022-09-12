KnowBe4_KMSAT Allows you to push and pull your external data to and from the KnowBe4 console.

## Configure KnowBe4 KMSAT Event Collector on Cortex XSOAR
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for KnowBe4KMSATEventCollector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection - for more information about how to generate API-Key please refer to https://support.knowbe4.com/hc/en-us/articles/360024863474-User-Event-API| True |
    | First fetch time interval | The time range to consider for the initial data fetch. \(&amp;lt;number&amp;gt; &amp;lt;unit&amp;gt;, e.g., 2 minutes, 2 hours, 2 days, 2 months, 2 years\). Default is 1 day. | False |
    | Events Fetch Interval | The Fetch interval, it's recommended to set it to 5 hours as there're not much events for this api and there's a 10 call daily-limit for basic api key. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | The vendor corresponding to the integration that produced the events. |  |  |
    | The product corresponding to the integration that produced the events. |  | False |

4. Click **Test** to validate the URLs, token, and connection.

**Important Notes**
The API-Key has a daily limit of 10 calls per seat.
Therefore, the default and adviced **Events Fetch Interval** is 5 hours and 
**First fetch time interval** is 1 day.