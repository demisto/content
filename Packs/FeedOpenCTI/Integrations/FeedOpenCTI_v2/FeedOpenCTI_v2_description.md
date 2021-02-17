## Configure OpenCTI Feed v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpenCTI Feed v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL |  | True |
    | API Key |  | True |
    | Indicators Type to fetch | The indicator types to fetch. Out of the box indicator types supported in XSOAR are: "User-Account", "Domain", "Email-Address", "File-md5", "File-sha1", "File-sha256", "HostName", "IPV4-Addr", "IPV6-Addr", "Registry-Key-Value", and "URL". The rest will not cause automatic indicator creation in XSOAR. Please refer to the integration documentation for more information. The default is "ALL". | True |
    | Max. indicators per fetch (default is 500) |  | False |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Tags | Supports CSV values. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.