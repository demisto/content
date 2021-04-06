QSS integration helps you to fetch Cases from Q-SCMP and add new cases automatically through XSOAR.
This integration was integrated and tested with version 3.6 of Q-SCMP. Please contact your platform administrtor to enable Cortex XSOAR integration. 

## Configure QSS on Cortex XSOAR

1. Please contact your Q-SCMP platform administrtor to obtain Cortex **API Key** and **Server URL**. 
2. Navigate to **Settings** > **Integrations** > **Servers & Services**.
3. Search for QSS.
4. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://<Q-SCMP_service_host>) | True |
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
