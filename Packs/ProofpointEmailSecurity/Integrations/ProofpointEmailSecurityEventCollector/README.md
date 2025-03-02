Collects events for Proofpoint using the streaming API.
This integration was integrated and tested Proofpoint Email Security.

## Configure Proofpoint Email Security Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Proofpoint Email Security Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server Host | True |
    | Cluster ID | True |
    | API key | True |
    | Fetch interval in seconds | True |
    | Use system proxy settings | False |

4. Select **Long running instance**.
5. Click **Test** to validate the URLs, token, and connection.


## Commands
### proofpoint-es-get-last-run-results
***
Retrieves the results of a connection attempt to Proofpoint, indicating whether it was successful or failed and why. If event fetching has been initiated, this command provides the results of the most recent fetch attempt.