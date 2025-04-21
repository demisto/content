Active TLS fingerprinting using JARM

## Configure JARM in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### jarm-fingerprint
***
Calculate JARM fingerprint by scanning host with multiple TLS packets.


#### Base Command

`jarm-fingerprint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | FQDN or IP address to fingerprint. Also supports [https://fqdn:port] format. | Required | 
| port | Port to fingerprint. If provided overrides the port specified in the host parameter. Default is 443. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JARM.FQDN | String | FQDN of the host. | 
| JARM.IP | String | IP Address of the host. | 
| JARM.Port | Number | TCP port |
| JARM.Target | String | The host in the format [IP or FQDN]:Port | 
| JARM.Fingerprint | String | JARM fingerprint of the host. | 
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

#### Command Example
```!jarm-fingerprint host="google.com" port=443```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
            "Score": 0,
            "Type": "jarm",
            "Vendor": "JARM"
        }
    ],
    "JARM": {
        "FQDN": "google.com",
        "Fingerprint": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
        "Port": 443,
        "Target": "google.com:443"
    }
}
```

#### Human Readable Output

>### Results
>|FQDN|Fingerprint|Port|Target|
>|---|---|---|---|
>| google.com | 27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d | 443 | google.com:443 |