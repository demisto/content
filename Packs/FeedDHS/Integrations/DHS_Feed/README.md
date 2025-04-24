The Cybersecurity and Infrastructure Security Agency’s (CISA’s) free Automated Indicator Sharing (AIS) capability enables the exchange of cyber threat indicators, at machine speed, to the Federal Government community.
Use this version if your certificate supports TAXII 1 protocol.
## Configure DHS Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL |  | True |
| Key File as Text | For more information, visit https://us-cert.cisa.gov/ais. | True |
| Certificate File as Text | For more information, visit https://us-cert.cisa.gov/ais. | True |
| Feed Type |  | True |
| Filter by Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) fetch from feed. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Tags | Supports CSV values. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dhs-get-indicators
***
Get the indicators.


#### Base Command

`dhs-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 20. Default is 20. | Required | 
| tlp_color | The TLP color by which to filter the results. Possible values: "RED", "AMBER", "GREEN", "WHITE". Possible values are: RED, AMBER, GREEN, WHITE. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DHS.type | String | The indicator type \(e.g., IP, Domain, Email, URL, File\). | 
| DHS.value | string | The indicator. | 
| DHS.tlp | string | The traffic light protocol. | 


#### Command Example
```!dhs-get-indicators limit=2 tlp_color=GREEN```