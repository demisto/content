Log collecting for AUDIT events using the Duo API https://duo.com/docs/adminapi#logs.

## Configure Duo Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for Duo Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
|----|--------|----------|
| Server Host    | Duo API host (api-XXXXXXXX.duosecurity.com).   | True         |
| First fetch from API time   | The time to fetch from for the first run.     | True   |
| Integration key   | API integration key.   | True    |
| Secret key  | API secret key.  | True    |
| XSIAM request limit  | The maximum number of results to get from the API and to add to XSIAM. | True |
| Request retries  | The number of retries to perform in the API. (This is necessary because if there are too many retries, the API will return a "too many requests 429" error). | False        |

4. Click **Test** to validate the URLs, tokens, and connection.
