Active TLS fingerprinting using JARM

## Configure JARM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for JARM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| JARM.Fingerprint | String | JARM fingerprint of the host. | 


#### Command Example
```!jarm-fingerprint host="google.com" port=443```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Host": {
                "fqdn": "google.com",
                "ip": null,
                "port": 443
            },
            "Indicator": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
            "Score": 0,
            "Type": "jarm",
            "Vendor": "JARM"
        }
    ],
    "JARM": {
        "FQDN": "google.com",
        "Fingerprint": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
        "Port": 443
    }
}
```

#### Human Readable Output

>New JARM indicator was found: 27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d
