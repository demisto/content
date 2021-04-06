QSS integration helps you to fetch Cases from Q-SCMP and add new cases automatically through XSOAR.
This integration was integrated and tested with version xx of QSS
## Configure QSS on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for QSS.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://example.com) | True |
    | Fetch incidents | False |
    | Incident type | False |
    | Max fetch | False |
    | API Key | True |
    | Fetch cases with status (Open, Closed) | False |
    | Minimum severity of cases to fetch | False |
    | Flase positive cases to fetch | False |
    | Back time duration of cases to fetch (Hours) | True |
    | First fetch time | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
