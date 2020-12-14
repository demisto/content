Fetches indicators from a iDefense feed. You can filter returned indicators by indicator type, indicator severity, threat type, confidence, and malware family (each of these are an integration parameter).
Ingesting the indicator is being done in an incremental manner.
This feed integration was integrated and tested with version v2.61.1 of iDefense.

## Configure iDefense Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for iDefense Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | feed | Fetch indicators | False |
    | api_token | API Key | True |
    | feedReputation | Indicator Reputation | False |
    | feedReliability | Source Reliability | True |
    | tlp_color | Traffic Light Protocol Color | False |
    | feedExpirationPolicy |  | False |
    | feedExpirationInterval |  | False |
    | feedFetchInterval | Feed Fetch Interval | False |
    | feedIncremental | Incremental Feed | False |
    | fetch_time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
    | indicator_type | Indicator Type | True |
    | severity | Indicator Severity | False |
    | threat_type | Threat Type | False |
    | confidence_from | Confidence | False |
    | malware_family | Malware Family | False |
    | feedBypassExclusionList | Bypass exclusion list | False |
    | feedTags | Tags | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### idefense-get-indicators
***
Gets the feed indicators.


#### Base Command

`idefense-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!idefense-get-indicators limit=10```

#### Context Example
There is no context output for this command.

>#### Indicators
>|value|type|rawJSON|
>|---|---|---|
>| http://194.62.6.66/bins/nigga.arm5 | URL | confidence: 50<br/>display_text: http://194.62.6.66/bins/nigga.arm5<br/>files: {'confidence': 50, 'display_text': '03d9971156ef1acc5c40c275763e0ff8', 'key': '03d9971156ef1acc5c40c275763e0ff8', 'last_seen': '2020-12-13T23:28:40.000Z', 'relationship': 'deliveredFrom', 'relationship_created_on': '2020-12-13T17:13:34.000Z', 'relationship_last_published': '2020-12-06T02:07:22.000Z', 'type': 'file', 'uuid': '8e87ccbe-c440-4dde-9026-842b81b27bc5', 'href': '/rest/fundamental/v0/8e87ccbe-c440-4dde-9026-842b81b27bc5'},<br/>{'confidence': 50, 'display_text': '6bb1b35a6fe477efda3a96bee2eaa229', 'key': '6bb1b35a6fe477efda3a96bee2eaa229', 'last_seen': '2020-12-13T21:26:46.000Z', 'relationship': 'deliveredFrom', 'relationship_created_on': '2020-12-12T23:01:59.000Z', 'relationship_last_published': '2020-12-06T02:07:22.000Z', 'type': 'file', 'uuid': 'fcbb6076-2921-43ef-bd2f-ed8d098279b8', 'href': '/rest/fundamental/v0/fcbb6076-2921-43ef-bd2f-ed8d098279b8'},<br/>{'confidence': 50, 'display_text': '92293cf63aa1188e118d00c806eb0dac', 'key': '92293cf63aa1188e118d00c806eb0dac', 'last_seen': '2020-12-13T20:08:24.000Z', 'relationship': 'deliveredFrom', 'relationship_created_on': '2020-12-12T21:01:14.000Z', 'relationship_last_published': '2020-12-06T02:07:22.000Z', 'type': 'file', 'uuid': '24645b9f-6b07-428c-b6ac-28fae50a00af', 'href': '/rest/fundamental/v0/24645b9f-6b07-428c-b6ac-28fae50a00af'}<br/>index_timestamp: 2020-12-13T23:31:03.848Z<br/>key: http://194.62.6.66/bins/nigga.arm5<br/>last_modified: 2020-12-13T23:29:13.000Z<br/>last_published: 2020-12-07T14:50:44.000Z<br/>last_seen: 2020-12-13T20:08:24.000Z<br/>last_seen_as: MALWARE_DOWNLOAD<br/>malware_family: <br/>replication_id: 1607902153340000001<br/>severity: 3<br/>threat_types: Cyber Crime<br/>type: url<br/>uuid: 71575698-b7ad-4db9-9895-b430181a6aa9<br/>arguments: <br/>path: bins,<br/>nigga.arm5 |
