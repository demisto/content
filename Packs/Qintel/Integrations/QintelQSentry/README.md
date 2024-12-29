QSentry queries help measure the likelihood that a user is masking their identity using publicly or privately available proxy or VPN services.  The returns also flag any known fraud associations.  QSentry aggregates data from Qintel’s proprietary Deep and DarkWeb research, as well as from commercially available anonymization services.
This integration was integrated and tested with version 4.0 of Qintel QSentry

## Configure QintelQSentry in Cortex


| **Parameter** | **Required** |
| --- | --- |
| QSentry API URL (optional) | False |
| Qintel Token | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Queries Qintel for IP reputation data


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested | 
| DBotScore.Type | String | The indicator type | 
| DBotScore.Vendor | String | The vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 
| IP.Address | string | IP address | 
| IP.ASN | string | The autonomous system name for the IP address | 
| IP.ASOwner | string | The autonomous system name for the IP address | 
| IP.Malicious.Vendor | string | The vendor reporting the IP address as malicious | 
| IP.Malicious.Description | string | A description explaining why the IP address was reported as malicious | 
| Qintel.IP.Address | boolean | IP address | 
| Qintel.IP.Tags | string | Proxy tags | 
| Qintel.IP.Description | string | IP description | 
| Qintel.IP.LastObserved | string | Last observed time | 


#### Command Example
```!ip ip=192.168.35.100```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "192.168.35.100",
        "Score": 2,
        "Type": "ip",
        "Vendor": "Qintel"
    },
    "IP": {
        "ASN": 65000,
        "ASOwner": "Some Service Provider",
        "Address": "192.168.35.100",
        "Malicious": {
            "Description": "Indicator is associated with a criminal proxy/vpn",
            "Vendor": "Qintel"
        },
        "Tags": [
            "Proxy",
            "Vpn"
        ]
    },
    "Qintel": {
        "IP": {
            "Address": "192.168.35.100",
            "Description": [
                "this ip address has been associated with a vpn network that offers paid access to users. it is advertised in online underground spaces.",
                "This ip address has been associated with a proxy network that offers paid access to users and is advertised within the online underground. it is commonly utilized by criminal actors to conduct compromised credential checking and the proxy network is hosted on a botnet infrastructure. ip address is likely an infected machine."
            ],
            "LastObserved": "2021-08-31 11:00:00",
            "Tags": [
                "Proxy",
                "Vpn"
            ]
        }
    }
}
```

#### Human Readable Output

>### Qintel results for IP: 192.168.35.100
>|ASN|AS Owner|Tags|Description|Last Observed|
>|---|---|---|---|---|
>| 65000 | Some Service Provider | <br/>Proxy,<br/>Vpn | This ip address has been associated with a vpn network that offers paid access to users. it is advertised in online underground spaces.,<br/>This ip address has been associated with a proxy network that offers paid access to users and is advertised within the online underground. it is commonly utilized by criminal actors to conduct compromised credential checking and the proxy network is hosted on a botnet infrastructure. ip address is likely an infected machine. | 2021-08-31 11:00:00 |
