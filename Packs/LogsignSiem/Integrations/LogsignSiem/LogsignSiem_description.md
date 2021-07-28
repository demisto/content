Logsign SIEM provides comprehensive visibility and control of your data lake by allowing security analysts to collect and store unlimited data, investigate and detect threats, and respond automatically.

This integration was integrated and tested with version 4.6.x of Logsign SIEM

## Configure Logsign SIEM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Logsign SIEM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://192.168.0.1) | Logsign SIEM API URL | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Last Run Time (ISO8601 format with UTC) | Last run time format like '%Y-%m-%dT%H:%M:%SZ' | True |
    | First Fetch Time (default 1 hour) | First Fetch Time \(e.g 1 hour\) | False |
    | isFetch |  | False |
    | Max Fetch | Maximum number of incidents per fetch \(Recommended less than 200\) | False |

4. Click **Test** to validate the URLs, token, and connection.