This integration enables reputation checks against IPs from Barracuda Reputation Block List (BRBL)
This integration was integrated and tested with Barracuda Reputation Block List (BRBL)
## Configure Barracuda Reputation Block List (BRBL) in Cortex



## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| DBotScore.Indicator | String | The indicator itself | 
| DBotScore.Score | Number | Score | 
| DBotScore.Type | String | Type of the indicator | 
| DBotScore.Vendor | String | Vendor information | 
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
