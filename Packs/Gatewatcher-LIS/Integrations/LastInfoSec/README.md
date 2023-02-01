This integration allow to interact with the Gatewatcher LastInfoSec product via API.
This integration was integrated and tested with version 2 of LastInfoSec

## Configure LastInfoSec on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for LastInfoSec.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | LastInfoSec API token | The API Key to use for connection | True |
    | Check the TLS certificate |  | False |
    | Http proxy |  | False |
    | Https proxy |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gw-lis-get-by-minute
***
Retrieve the data from Gatewatcher CTI feed by minute.
Max 1440 minutes.


#### Base Command

`gw-lis-get-by-minute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Minute |  Number of minutes to get.<br/>Max 1440 minutes. | Required | 
| Categories | Filter IoC by categories. Possible values are: phishing, malware, trojan, exploit, ransom, ransomware, tool, keylogger. | Optional | 
| Type | Filter IoC by type. Possible values are: SHA1, SHA256, MD5, URL, Host. | Optional | 
| Mode | Filter IoC by mode. Possible values are: detection, hunting. | Optional | 
| Risk | Filtre IoC by risk. Possible values are: Informational, Malicious, Suspicious, High suspicious. | Optional | 
| TLP | Filtre IoC by TLP. Possible values are: green, white. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LIS.GetByMinute.Value | String | Value | 

##### Command Example

```!gw-lis-get-by-minute Minute="5"```

#### Context Example

```json
{
    "Value": [
      "8445e9539c776b7538e2a9a665f5a1506df9ec5bbd1bf3a8a88cc6e572afda64",
      "19663abcbb5a271e0893a5f9a009a1dd.exe",
      "19663abcbb5a271e0893a5f9a009a1dd",
      "17159ee4eecfd627b3e9ce3ddabd09be32d7b79f"
    ]
}
```

#### Get IoC by value
|Value                                                           |
|----------------------------------------------------------------|
|8445e9539c776b7538e2a9a665f5a1506df9ec5bbd1bf3a8a88cc6e572afda64|
|19663abcbb5a271e0893a5f9a009a1dd.exe                            |
|19663abcbb5a271e0893a5f9a009a1dd                                |
|17159ee4eecfd627b3e9ce3ddabd09be32d7b79f                        |


### gw-lis-get-by-value
***
Allows you to search for an IOC (url, hash, host) or a vulnerability in the Gatewatcher CTI database. If the data is known, only the IOC corresponding to the value will be returned.


#### Base Command

`gw-lis-get-by-value`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Value | Value to be search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LIS.GetByValue.Categories | String | Categories | 
| LIS.GetByValue.Risk | String | Risk | 
| LIS.GetByValue.TLP | String | TLP | 
| LIS.GetByValue.Type | String | Type | 
| LIS.GetByValue.UsageMode | String | UsageMode | 
| LIS.GetByValue.Value | String | Value | 
| LIS.GetByValue.Vulnerabilities | String | Vulnerabilities | 

##### Command Example

```!gw-lis-get-by-value Value="b71c7db7c4b20c354f63820df1f5cd94dbec97849afa690675d221964b8176b5"```

#### Context Example

```json
{
    "Categories": "malware",
    "Risk": "Suspicious",
    "TLP": "white",
    "Type": "SHA256",
    "UsageMode": "detection",
    "Value": "b71c7db7c4b20c354f63820df1f5cd94dbec97849afa690675d221964b8176b5",
    "Vulnerabilities": ""
}
```

#### Get IoC by value
|Categories|Risk|TLP|Type|UsageMode|Value|Vulnerabilities|
|---|---|---|---|---|---|---|
| malware | Suspicious | white | SHA256 | detection | b71c7db7c4b20c354f63820df1f5cd94dbec97849afa690675d221964b8176b5 |  |