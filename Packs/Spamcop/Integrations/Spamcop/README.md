SpamCop is an email spam reporting service. The integration allows checking the reputation of an IP address.
This integration was integrated and tested with Spamcop.

## Configure Spamcop in Cortex



## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Get IP details from Spamcop service


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP which details you want to find | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Spamcop.IP | String | IP details | 


#### Command Example
```!ip ip=xxx.xxx.xxx.xxx```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "xxx.xxx.xxx.xxx",
        "Score": 3,
        "Type": "ip",
        "Vendor": "Spamcop"
    },
    "IP": {
        "Address": "xxx.xxx.xxx.xxx",
        "Malicious": {
            "Description": null,
            "Vendor": "Spamcop"
        }
    },
    "Spamcop": {
        "IP": {
            "indicator": "xxx.xxx.xxx.xxx"
        }
    }
}
```

#### Human Readable Output

>### Results
>|indicator|
>|---|
>| xxx.xxx.xxx.xxx |