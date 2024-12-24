Ingest articles as incidents from Feedly into XSOAR.

## Configure Feedly on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IncidentsFeedly.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API key |  | False |
    | isFetch | Fetch incidents | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    |  |  | False |
    |  |  | False |
    | Stream ID | The stream id you want to fetch articles from. You can find it in Feedly by going to the stream, clicking on \`...\` &gt; \`Sharing\`, then \`Copy ID\` in the \`Feedly API Stream ID\` section. | True |
    | Days to fetch for first run | Number of days to fetch articles from when running the integration for the first time | True |
    | Incremental feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. The determination if the indicator is new or modified happens on the 3rd-party vendor's side, so only indicators that are new or modified are sent to Cortex XSOAR. Therefore, all indicators coming from these feeds are labeled new or modified. | False |

4. Click **Test** to validate the URLs, token, and connection.
