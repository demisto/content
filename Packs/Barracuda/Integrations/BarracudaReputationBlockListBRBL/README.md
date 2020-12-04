This integration enables reputation checks against IPs from Barracuda Reputation Block List (BRBL)
This integration was integrated and tested with Barracuda Reputation Block List (BRBL)
## Configure Barracuda Reputation Block List (BRBL) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Barracuda Reputation Block List (BRBL).
3. Click **Add instance** to create and configure a new integration instance.


4. Click **Test** to validate the connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Get IP Reputation


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP to look up | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ip | String | Get IP details from Barracuda\(BRBL\) service | 
| Barracuda.IP | String | IP details | 
| DbotScore.Indicator | String | The indicator itself | 
| DbotScore.Score | Number | Score | 
| DbotScore.Type | String | Type of the indicator | 
| DbotScore.Vendor | String | Vendor information | 
| IP.Address | String | IP address | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 


#### Command Example
```!ip ip=1.1.1.1```

#### Context Example
```json
{
    "Barracuda": {
        "IP": {
            "indicator": "1.1.1.1"
        }
    },
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Barracuda"
    },
    "IP": {
        "Address": "1.1.1.1"
    }
}
```

#### Human Readable Output

>### Results
>|indicator|
>|---|
>| 1.1.1.1 |

