Integration for Cyble IOCs feed
This integration was integrated and tested with version xx of Cyble
## Configure Cyble on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cyble.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://cyble.ai/api) |  | False |
    | API Key |  | False |
    | start date (e.g. 2021-01-15) |  | False |
    | end date (e.g. 2021-01-15). If empty; will use today's date |  | False |
    | CIDR, CVE, domain, email, FileHash-IMPHASH, FileHash-MD5, FileHash-PEHASH, FileHash-SHA1, FileHash-SHA256, FilePath, hostname, IPv4, IPv6, Mutex, NIDS, URI, URL, YARA, osquery, Ja3, Bitcoinaddress, Sslcertfingerprint) |  | False |
    |  |  | False |
    | from (index of record to start fetching from) |  | False |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyble-fetch-indicators
***
fetches indicators for cyble


#### Base Command

`cyble-fetch-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


