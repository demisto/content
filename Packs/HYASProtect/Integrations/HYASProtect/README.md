# HYAS Protect
HYAS Protect is a generational leap forward utilizing authoritative knowledge of attacker infrastructure including unrivaled domain-based intelligence to proactively protect enterprises from cyberattacks. HYAS Protect is deployed as a cloud-based DNS security solution or through API integration with existing solutions. HYAS Protect combines infrastructure expertise and multi-variant communication pattern analysis to deliver reputational verdicts for any domain and infrastructure, allowing enterprises to preempt attacks while proactively assessing risk in real-time. HYAS Protect can enforce security, block command and control (C2) communication used by malware, ransomware, and botnets, block phishing attacks, and deliver a high-fidelity threat signal that enhances an enterprise’s existing security and IT governance stack.

Use the HYAS Protect integration to get the verdict information for FQDN, IP Address and NameServer.
This integration was integrated and tested with version 1.0.0 of HYAS Protect.

## Configure HYAS Protect in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| HYAS Protect Api Key | HYAS Protect API Key. | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
| Use system proxy settings | Use system proxy settings. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hyas-get-domain-verdict
***
Returns verdict information for the provided Domain.


#### Base Command

`hyas-get-domain-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the indicator score. | 
| HYAS.DomainVerdict.verdict | String | Verdict for the provided Domain. | 
| HYAS.DomainVerdict.reasons | Unknown | Verdict Reasons the provided Domain. | 


#### Command Example
```!hyas-get-domain-verdict domain="google.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "google.com",
        "Score": 1,
        "Type": "domain",
        "Vendor": "HYAS Protect"
    },
    "Domain": {
        "Name": "google.com"
    },
    "HYAS": {
        "DomainVerdict": [
            {
                "reasons": [
                    "This domain is trusted",
                    "This registrar is trusted"
                ],
                "verdict": "ALLOW"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS Domain verdict for google.com
>|Verdict|Reasons|
>|---|---|
>| ALLOW | This domain is trusted,<br/>This registrar is trusted |


### hyas-get-ip-verdict
***
Returns verdict information for the provided IP Address.


#### Base Command

`hyas-get-ip-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the indicator score. | 
| HYAS.IPVerdict.verdict | String | Verdict for the provided IP Address. | 
| HYAS.IPVerdict.reasons | Unknown | Verdict Reasons for the provided IP Address. | 


#### Command Example
```!hyas-get-ip-verdict ip="8.8.8.8"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 1,
        "Type": "ip",
        "Vendor": "HYAS Protect"
    },
    "HYAS": {
        "IPVerdict": [
            {
                "reasons": [],
                "verdict": "ALLOW"
            }
        ]
    },
    "IP": {
        "Address": "8.8.8.8"
    }
}
```

#### Human Readable Output

>### HYAS IP verdict for 8.8.8.8
>|Verdict|
>|---|
>| ALLOW |


### hyas-get-fqdn-verdict
***
Returns verdict information for the provided FQDN.


#### Base Command

`hyas-get-fqdn-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fqdn | FQDN value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the indicator score. | 
| HYAS.FQDNVerdict.verdict | String | Verdict for for the provided FQDN. | 
| HYAS.FQDNVerdict.reasons | Unknown | Verdict Reasons for the provided FQDN. | 


#### Command Example
```!hyas-get-fqdn-verdict fqdn="www.google.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "www.google.com",
        "Score": 1,
        "Type": "domain",
        "Vendor": "HYAS Protect"
    },
    "Domain": {
        "Name": "www.google.com"
    },
    "HYAS": {
        "FQDNVerdict": [
            {
                "reasons": [
                    "This domain is trusted",
                    "This registrar is trusted"
                ],
                "verdict": "ALLOW"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS FQDN verdict for www.google.com
>|Verdict|Reasons|
>|---|---|
>| ALLOW | This domain is trusted,<br/>This registrar is trusted |


### hyas-get-nameserver-verdict
***
Returns verdict information for the provided Nameserver.


#### Base Command

`hyas-get-nameserver-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nameserver | Nameserver value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the indicator score. | 
| HYAS.NameserverVerdict.verdict | String | Verdict for the provided Nameserver. | 
| HYAS.NameserverVerdict.reasons | Unknown | Verdict Reasons for the provided Nameserver. | 


#### Command Example
```!hyas-get-nameserver-verdict nameserver="ns1.example.com"```

#### Context Example
```json
{
    "HYAS": {
        "NameserverVerdict": [
            {
                "reasons": [],
                "verdict": "ALLOW"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS Nameserver verdict for ns1.example.com
>|Verdict|
>|---|
>| ALLOW |
