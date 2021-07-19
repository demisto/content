Use the MITRE ATT&CK Feed integration to fetch indicators from MITRE ATT&CK.
For more information click [here](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via).

## Configure MITRE ATT&CK Feed on XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MITRE ATT&CK Feed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| includeAPT | This option will also create indicators using APT / actor name references if they are part of a MITRE Intrusion Set | False |
| feedReputation | The indicator reputation (defaults to 'None'). | False |
| feedReliability | The source's reliability. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | The feed's expiration policy. | False |
| feedExpirationInterval | The interval after which the feed expires. | False |
| feedFetchInterval | The feed fetch interval. | False |
| feedBypassExclusionList | Whether to bypass exclusion list. | False |
| insecure | Whether to trust any certificate (not secure). | False |
| proxy | Whether to use the system proxy settings. | False |
| Create relationships | Create relationships between indicators as part of Enrichment. | False |

4. Click **Test** to validate the connection.

#### Feed timeouts:
MITRE enforce a rate limit for connecting to their taxii server. Ensure that your fetch interval is reasonable, otherwise you will receive connection errors.

## Commands
You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get Indicators
***
Gets the indicators from MITRE ATT&CK.

Note: This command does not create indicators within Cortex XSOAR.

##### Base Command

`mitre-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10. | Optional | 
| raw | Enabling raw will also output the raw content of each indicator | Optional | 


##### Context Output

The context is output as:

- MITRE *(dict)*
    - ATT&CK *(list)*

Each item in the "ATT&CK" list contains the following keys:
- fields *(any fields that the indicator will attempt to map into the indicator)*
- rawJSON *(the raw JSON of the indicator)*
- score *(the indicator score)*
- type *(the type of indicator - will always be "MITRE ATT&CK")*
- value *(the indicator value, for example "T1134")*
     

##### Command Example
```!mitre-get-indicators limit=2```


##### Human Readable Output
### MITRE ATT&CK Indicators:
| Value | Score| Type |
| ----- | ---- | ---- |
| T1531 | 0 | MITRE ATT&CK |
| T1506 | 0 | MITRE ATT&CK |



| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | Indicator to lookup | Required |  


##### Context Output

The context is output as:

- DBotScore
- MITRE *(dict)*
    - ATT&CK *(list)* 

Each item in the "ATT&CK" list contains the customFields that are mapped into the indicator (each beginning with 'mitre')
     

### MITRE Show Feeds
***
Displays the available feeds from the MITRE taxii service.

##### Base Command

`mitre-showfeeds`
##### Input

There are no inputs  

##### Context Output

There is no context output


##### Command Example
```!mitre-showfeeds```


##### Human Readable Output
### MITRE ATT&CK Feeds:
| Name | ID |
| ---- | --- |
| Enterprise ATT&CK | 95ecc380-afe9-11e4-9b6c-751b66dd541e |
| PRE-ATT&CK | 062767bd-02d2-4b72-84ba-56caef0f8658 |
| Mobile ATT&CK | 2f669986-b40b-4423-b720-4396ca6a462b |
