Reco is a Saas security solution that protects your data from accidental leaks and malicious attacks.
## Configure Reco on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Reco.
 Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description**                                                            | **Required** |
    |----------------------------------------------------------------------------| --- | --- |
    | apitoken | API Token                                                                  | True |
    | api_host | API Host without schema. Default: `https:/{{host}}.reco.ai`                | True
    | first_fetch | First fetch timestamp \(`<number>` `<time unit>`, e.g., 12 hours, 7 days\) | False |
    | incidentType | Incident type                                                              | False |
    | isFetch | Fetch incidents                                                            | False |
    | max_fetch | Max fetch                                                                  | False |
    | insecure | Trust any certificate \(not secure\)                                       | False |
    | proxy | Use system proxy settings                                                  | False |

3. Click **Test** to validate the URLs, token, and connection.


