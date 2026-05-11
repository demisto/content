DeCYFIR API's provides External Threat Landscape Management insights.
This integration was integrated and tested with version v1 of DeCYFIR Feed

## Configure DeCYFIR Indicators & Threat Intelligence Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| DeCYFIR Server URL (e.g. <https://decyfir.cyfirma.com>) |  | True |
| DeCYFIR API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### decyfir-get-indicators

***
Gets indicators from the feed.

#### Base Command

`decyfir-get-indicators`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### decyfir-ip-get

***
Get IP indicators from CYFIRMA.

#### Base Command

`decyfir-ip-get`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example
```!decyfir-ip-get```

#### Human Readable Output
> IP indicators retrieved successfully.

### decyfir-domain-get

***
Get Domain indicators from CYFIRMA.

#### Base Command

`decyfir-domain-get`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example
```!decyfir-domain-get```

#### Human Readable Output
> Domain indicators retrieved successfully.

### decyfir-url-get

***
Get URL indicators from CYFIRMA.

#### Base Command

`decyfir-url-get`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example
```!decyfir-url-get```

#### Human Readable Output
> URL indicators retrieved successfully.

### decyfir-file-get

***
Get File Hash indicators from CYFIRMA.

#### Base Command

`decyfir-file-get`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example
```!decyfir-file-get```

#### Human Readable Output
> File indicators retrieved successfully.