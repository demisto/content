Use this feed to retrieve the discovered IPs/Domains/Certificates from Cortex Xpanse asset database.
This integration was integrated and tested with version 2.5 of Cortex Xpanse.

## Configure Xpanse Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The web UI with \`api-\` appended to front \(e.g., https://api-xsiam.paloaltonetworks.com\). For more information, see https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis. | True |
| API Key ID | For more information, see https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis.  Only standard API key type is supported. | True |
| API Key |  | True |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Tags | Supports CSV values. | False |
| Feed Fetch Interval |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xpanse-get-indicators

***
Retrieves a limited number of indicators.

#### Base Command

`xpanse-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. | Required | 
| ip | Retrieve discovered IPs. Default is yes. | Optional | 
| domain | Retrieve discovered domains. Default is yes. | Optional | 
| certificate | Retrieve discovered certificates. Default is yes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.Indicators.Name | String | The name of the indicator. | 
| ASM.Indicators.Description | String | The description of the indicator. | 
| ASM.Indicators.Type | String | The type of the indicator. | 

#### Command example
```!xpanse-get-indicators limit=1 ip=yes certificate=no domain=no```
#### Context Example
```json
{
    "ASM": {
        "Indicators": {
            "Description": "1.1.1.1 indicator of asset type IP from Cortex Xpanse",
            "Name": "1.1.1.1",
            "Type": "IP"
        }
    }
}
```

#### Human Readable Output

>### Xpanse indicators
>|Name|Type|Description|
>|---|---|---|
>| 1.1.1.1 | IP | 1.1.1.1 indicator of asset type IP from Cortex Xpanse |
