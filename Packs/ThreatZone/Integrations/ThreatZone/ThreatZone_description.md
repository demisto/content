## Configure ThreatZone on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **ThreatZone**.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter**                      | **Required** |
   | :----------------------------------- | -------------- |
   | Server URL                         | True         |
   | API Key                            | True         |
   | Trust any certificate (not secure) | False        |
   | Use system proxy settings          | False        |

4. Enter either the ThreatZone instance root (for example, `https://app.threat.zone`) or its `/public-api` URL. The integration normalizes the suffix automatically and does not fall back to the ThreatZone cloud when this value is empty.
5. Click **Test** to validate the server URL, API key, and connection.

The integration uses the official ThreatZone Python SDK for submissions, configuration discovery, report and telemetry retrieval, and file downloads. High-volume behaviour, syscall, and network commands return one bounded page or window per execution.