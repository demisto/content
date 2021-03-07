Multi-Vector Cyber Attack, Breach and Attack Simulation.
This integration was integrated and tested with Cymulate platform. 

## Configure cymulate_v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for cymulate_v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API token |  | True |
    | Fetch incidents |  | False |
    | Fetch category | Choose one or more categories to fetch. | False |
    | Incident type |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | None |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cymulate-exfiltration-template-list
***
Retrieve the exfiltration template list.


#### Base Command

`cymulate-exfiltration-template-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Exfiltration.Template.id | String | Template ID. | 
| Cymulate.Exfiltration.Template.name | String | Template name. | 


#### Command Example
```!cymulate-exfiltration-template-list```

#### Context Example
```json
{
    "Cymulate": {
        "Exfiltration": {
            "Templates": [
                {
                    "_id": "5df0e79b85a00138dc648e75",
                    "name": "Cymulate Best Practice"
                },
                {
                    "_id": "5df0e7d585a00138dc648e8f",
                    "name": "Cloud Services"
                },
                {
                    "_id": "5df0e80885a00138dc648ea7",
                    "name": "Network Protocols"
                },
                {
                    "_id": "5df0e82e85a00138dc648ebb",
                    "name": "Email"
                },
                {
                    "_id": "5df25b3696fa2af420a379b9",
                    "name": "Physical"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Exfiltration templates list:
>|_id|name|
>|---|---|
>| 5df0e79b85a00138dc648e75 | Cymulate Best Practice |
>| 5df0e7d585a00138dc648e8f | Cloud Services |
>| 5df0e80885a00138dc648ea7 | Network Protocols |
>| 5df0e82e85a00138dc648ebb | Email |
>| 5df25b3696fa2af420a379b9 | Physical |
>| 5ea72aaf4df7c922f7e77d64 | Test |
>| 6016f4494d25d842b9a7c6b0 | avi-test12 |
>| 6016f612463265434cf563f0 | zxcxzcasd |


### cymulate-exfiltration-start
***
Create a new exfiltration assessment.


#### Base Command

`cymulate-exfiltration-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The ID of the template to run the exfiltration Assessment with. | Required | 
| agent_name | agent name to run simulation attacks. | Required | 
| schedule | whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent.For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Exfiltration.id | String | New exfiltration assessment creation ID. | 
| Cymulate.Exfiltration.success | Boolean | New exfiltration assessment creation success status. | 


#### Command Example
```!cymulate-exfiltration-start template_id="5df0e79b85a00138dc648e75" agent_name="avihaiby@cymulate.com" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "Exfiltration": {
            "Assessment": {
                "id": "123",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Starting exfiltration assessment:
>|id|success|
>|---|---|
>| "123" | true |


### cymulate-exfiltration-stop
***
Stop a running exfiltration assessment.


#### Base Command

`cymulate-exfiltration-stop`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Exfiltration.data | String | New exfiltration assessment stopping data. | 
| Cymulate.Exfiltration.success | Boolean | New exfiltration assessment stopping success status. | 


#### Command Example
```!cymulate-exfiltration-stop```

#### Context Example
```json
{
    "Cymulate": {
        "Exfiltration": {
            "Assessment": {
                "data": "no running attacks",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Stopping exfiltration assessment:
>|data|success|
>|---|---|
>| no running attacks | true |


### cymulate-exfiltration-status
***
Get exfiltration assessment status.


#### Base Command

`cymulate-exfiltration-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | Assessment ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Exfiltration.id | String | New exfiltration assessment stop ID. | 
| Cymulate.Exfiltration.inProgress | Boolean | Whether the assessment is in progress. | 
| Cymulate.Exfiltration.progress | Number | Percentage of the progress of the assessment. | 
| Cymulate.Exfiltration.categories | String | Categories. | 


#### Command Example
```!cymulate-exfiltration-status assessment_id="id_123"```

#### Context Example
```json
{
    "Cymulate": {
        "Exfiltration": {
            "Assessment": {
                "addresses": null,
                "categories": [
                    "http",
                    "https",
                    "dns",
                    "dns-tunneling",
                    "icmp",
                    "outlook",
                    "device",
                    "telnet",
                    "sftp",
                    "slack",
                    "googledrive",
                    "onedrive",
                    "port_scanning",
                    "msteams",
                    "gmail",
                    "gitlab",
                    "azure_blob",
                    "aws_s3_bucket",
                    "github",
                    "googlestorage",
                    "browsinghttps",
                    "browsinghttp"
                ],
                "id": "id_123",
                "inProgress": false,
                "progress": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Exfiltration assessment status:
>|categories|id|inProgress|progress|
>|---|---|---|---|
>| http,<br/>https,<br/>dns,<br/>dns-tunneling,<br/>icmp,<br/>outlook,<br/>device,<br/>telnet,<br/>sftp,<br/>slack,<br/>googledrive,<br/>onedrive,<br/>port_scanning,<br/>msteams,<br/>gmail,<br/>gitlab,<br/>azure_blob,<br/>aws_s3_bucket,<br/>github,<br/>googlestorage,<br/>browsinghttps,<br/>browsinghttp | id_123 | false | 0 |


### cymulate-email-gateway-template-list
***
Retrieve the email gateway template list.


#### Base Command

`cymulate-email-gateway-template-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EmailGateway.Template.id | String | Template ID. | 
| Cymulate.EmailGateway.Template.name | String | Template name. | 


#### Command Example
```!cymulate-email-gateway-template-list```

#### Context Example
```json
{
    "Cymulate": {
        "EmailGateway": {
            "Templates": [
                {
                    "_id": "5c6920853659191ccf6858fc",
                    "name": "free assessment"
                },
                {
                    "_id": "5c6920853659191ccf6858fb",
                    "name": "cymulate best practice"
                },
                {
                    "_id": "5db5ab6e79a0bf2feedaf9a7",
                    "name": "cymulate best practice - high risk"
                },
                {
                    "_id": "5c73b2ce3febfc300976c6e3",
                    "name": "exploits"
                },
                {
                    "_id": "5c7f96963febfc300976c7be",
                    "name": "malwares"
                },
                {
                    "_id": "5c7f977bc9545f79ea8b03c0",
                    "name": "ransomwares"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Email gateway templates list:
>|_id|name|
>|---|---|
>| 5c6920853659191ccf6858fc | free assessment |
>| 5c6920853659191ccf6858fb | cymulate best practice |
>| 5db5ab6e79a0bf2feedaf9a7 | cymulate best practice - high risk |
>| 5c73b2ce3febfc300976c6e3 | exploits |
>| 5c7f96963febfc300976c7be | malwares |
>| 5c7f977bc9545f79ea8b03c0 | ransomwares |
>| 5c7f99c2c9545f79ea8b0a49 | links |
>| 5c6968ec3659191ccf68592a | executables payloads |
>| 5c7f995bc9545f79ea8b090a | worms |
>| 5c6968e43659191ccf685929 | office payloads |
>| 5ccb0c2df8a3d30d0261ac6a | Custom template |
>| 5ccec96170ed8f6e3bdb2011 | noam t |
>| 5cd018d1ce0a6b4961bc824e | My Template |
>| 5cdc1a839eec3d5a6b01bb62 | Test1 |
>| 5cdcc2e339fb4c6a78333f58 | test |
>| 5d3468854e04f968c32fb17d | dd |
>| 5d761cd6d464e5719157bbe6 | sdas |
>| 5de3d21e6ea80d7ba047b4b1 | TEST |
>| 5e8247a8eb708b650ea101ba | asd123 |
>| 5ea20cabeaf9174534b6125d | MDShortTest |
>| 5f703f3e31628e1982b8fbbe | David-Test |
>| 5fe202f87261ed1a019c7f8f | David - Links |


### cymulate-email-gateway-start
***
Create a new email gateway assessment.


#### Base Command

`cymulate-email-gateway-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The ID of the template to run the email gateway assessment with. | Required | 
| agent_email | agent email. | Required | 
| schedule | whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent.For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EmailGateway.id | String | New email gateway assessment creation ID. | 
| Cymulate.EmailGateway.success | Boolean | New email gateway assessment creation success status. | 


#### Command Example
```!cymulate-email-gateway-start template_id="5c6920853659191ccf6858fc" agent_email="cymulatetests@cymulate.com" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "EmailGateway": {
            "Assessment": {
                "id": "603ba991c3d4b76ab14dda18",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Starting email gateway assessment:
>|id|success|
>|---|---|
>| 603ba991c3d4b76ab14dda18 | true |


### cymulate-email-gateway-stop
***
Stop a running exfiltration assessment.


#### Base Command

`cymulate-email-gateway-stop`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EmailGateway.data | String | Email gateway assessment stopping data. | 
| Cymulate.EmailGateway.success | Boolean | Email gateway assessment stopping success status. | 


#### Command Example
```!cymulate-email-gateway-stop```

#### Context Example
```json
{
    "Cymulate": {
        "EmailGateway": {
            "Assessment": {
                "data": "no running attacks",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Stopping email gateway assessment:
>|data|success|
>|---|---|
>| no running attacks | true |


### cymulate-email-gateway-status
***
Get the email gateway assessment status.


#### Base Command

`cymulate-email-gateway-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | Assessment ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EmailGateway.id | String | Email gateway assessment ID. | 
| Cymulate.EmailGateway.success | Boolean | Whether the assessment was successful. | 
| Cymulate.EmailGateway.inProgress | Boolean | Whether the assessment is in progress. | 
| Cymulate.EmailGateway.progress | Number | Percentage of the progress of the assessment. | 
| Cymulate.EmailGateway.addresses | String | Addresses. | 


#### Command Example
```!cymulate-email-gateway-status assessment_id="602d47f5fd72ea058cd63538"```

#### Context Example
```json
{
    "Cymulate": {
        "EmailGateway": {
            "Assessment": {
                "addresses": [
                    "cymulatetests@cymulate.com"
                ],
                "categories": [
                    "worm"
                ],
                "id": "602d47f5fd72ea058cd63538",
                "inProgress": false,
                "progress": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Email gateway assessment status:
>|addresses|categories|id|inProgress|progress|
>|---|---|---|---|---|
>| cymulatetests@cymulate.com | worm | 602d47f5fd72ea058cd63538 | false | 0 |


### cymulate-endpoint-security-template-list
***
Retrieve the endpoint security template list.


#### Base Command

`cymulate-endpoint-security-template-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EndpointSecurity.Template.id | String | Template ID. | 
| Cymulate.EndpointSecurity.Template.name | String | Template name. | 


#### Command Example
```!cymulate-endpoint-security-template-list```

#### Context Example
```json
{
    "Cymulate": {
        "EndpointSecurity": {
            "Templates": [
                {
                    "_id": "5c87a26f548a3c7c4c184a5e",
                    "name": "Free Assessment"
                },
                {
                    "_id": "5c97a50c5727c58a295d0459",
                    "name": "Cymulate Best Practice"
                },
                {
                    "_id": "5e98461d312a740ee4839700",
                    "name": "DLL Side loading"
                },
                {
                    "_id": "5c87a314548a3c7c4c184a5f",
                    "name": "Cymulate Behavior-based"
                },
                {
                    "_id": "5c87a314548a3c7c4c184a60",
                    "name": "Cymulate Signature-based"
                },
                {
                    "_id": "5c97a5705727c58a295d0465",
                    "name": "Cymulate Ransomware Behavior-based"
                },
                {
                    "_id": "5c97a5a55727c58a295d0467",
                    "name": "Cymulate Worm Behavior-based"
                },
                {
                    "_id": "5c97a5a55727c58a295d0468",
                    "name": "Cymulate Trojan Behavior-based"
                },
                {
                    "_id": "5ee20ab44c429549e7175304",
                    "name": "rootkit"
                },
                {
                    "_id": "5dc29419d4d40f54a011ebaf",
                    "name": "dll inj"
                },
                {
                    "_id": "5dc4b3c4610d050446c6b906",
                    "name": "Mundo Hacker Academy"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Endpoint security templates list:
>|_id|name|
>|---|---|
>| 5c87a26f548a3c7c4c184a5e | Free Assessment |
>| 5c97a50c5727c58a295d0459 | Cymulate Best Practice |
>| 5e98461d312a740ee4839700 | DLL Side loading |
>| 5c87a314548a3c7c4c184a5f | Cymulate Behavior-based |
>| 5c87a314548a3c7c4c184a60 | Cymulate Signature-based |
>| 5c97a5705727c58a295d0465 | Cymulate Ransomware Behavior-based |
>| 5c97a5a55727c58a295d0467 | Cymulate Worm Behavior-based |
>| 5c97a5a55727c58a295d0468 | Cymulate Trojan Behavior-based |
>| 5ee20ab44c429549e7175304 | rootkit |
>| 5dc29419d4d40f54a011ebaf | dll inj |
>| 5dc4b3c4610d050446c6b906 | Mundo Hacker Academy |


### cymulate-endpoint-security-start
***
Create a new endpoint security assessment.


#### Base Command

`cymulate-endpoint-security-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The ID of the template to run the endpoint security assessment with. | Required | 
| agent_name | agent name. | Required | 
| schedule | whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent.For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EndpointSecurity.id | String | New endpoint security assessment creation ID. | 
| Cymulate.EndpointSecurity.success | Boolean | New endpoint security assessment creation success status. | 


#### Command Example
```!cymulate-endpoint-security-start template_id="5c87a26f548a3c7c4c184a5e" agent_name="avihaiby@cymulate.com" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "EndpointSecurity": {
            "Assessment": {
                "id": "id_234",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Starting endpoint security assessment:
>|id|success|
>|---|---|
>| id_234 | true |


### cymulate-endpoint-security-stop
***
Stop a running endpoint security assessment.


#### Base Command

`cymulate-endpoint-security-stop`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EndpointSecurity.data | String | Endpoint security assessment stopping data. | 
| Cymulate.EndpointSecurity.success | Boolean | Endpoint Security assessment stopping success status. | 


#### Command Example
```!cymulate-endpoint-security-stop```

#### Context Example
```json
{
    "Cymulate": {
        "EndpointSecurity": {
            "Assessment": {
                "data": "no running attacks",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Stopping endpoint security assessment:
>|data|success|
>|---|---|
>| no running attacks | true |


### cymulate-endpoint-security-status
***
Get the endpoint security assessment status.


#### Base Command

`cymulate-endpoint-security-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | Assessment ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EndpointSecurity.id | String | Endpoint security assessment ID. | 
| Cymulate.EndpointSecurity.success | Boolean | Whether the assessment was successful. | 
| Cymulate.EndpointSecurity.inProgress | Boolean | Whether the assessment is in progress. | 
| Cymulate.EndpointSecurity.progress | Number | Percentage of the progress of the assessment. | 
| Cymulate.EndpointSecurity.addresses | String | Addresses. | 


#### Command Example
```!cymulate-endpoint-security-status assessment_id="id_345"```

#### Context Example
```json
{
    "Cymulate": {
        "EndpointSecurity": {
            "Assessment": {
                "addresses": null,
                "categories": [
                    "ransomware"
                ],
                "id": "id_345",
                "inProgress": false,
                "progress": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Endpoint security assessment status:
>|categories|id|inProgress|progress|
>|---|---|---|---|
>| ransomware | id_345 | false | 0 |


### cymulate-waf-template-list
***
Retrieve the WAF template list.


#### Base Command

`cymulate-waf-template-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.WAF.Template.id | String | Template ID. | 
| Cymulate.WAF.Template.name | String | Template name. | 


#### Command Example
```!cymulate-waf-template-list```

#### Context Example
```json
{
    "Cymulate": {
        "WAF": {
            "Templates": [
                {
                    "_id": "5edf7ddfef621bbc252498f3",
                    "name": "free assessment"
                },
                {
                    "_id": "5edf7547ef621bbc25248d97",
                    "name": "Cymulate Best Practice"
                },
                {
                    "_id": "5eea1fb754b285889325b81b",
                    "name": "File Inclusion"
                },
                {
                    "_id": "5ee0726cef621bbc25251d7d",
                    "name": "XSS"
                },
                {
                    "_id": "5fb65327f6ce656dbc7f9cf1",
                    "name": "SSRF"
                },
                {
                    "_id": "5ee0726cef621bbc25251d7a",
                    "name": "SQL Injection"
                },
                {
                    "_id": "5eea1fb754b285889325b818",
                    "name": "Command Injection"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### WAF templates list:
>|_id|name|
>|---|---|
>| 5edf7ddfef621bbc252498f3 | free assessment |
>| 5edf7547ef621bbc25248d97 | Cymulate Best Practice |
>| 5eea1fb754b285889325b81b | File Inclusion |
>| 5ee0726cef621bbc25251d7d | XSS |
>| 5fb65327f6ce656dbc7f9cf1 | SSRF |
>| 5ee0726cef621bbc25251d7a | SQL Injection |
>| 5eea1fb754b285889325b818 | Command Injection |


### cymulate-waf-start
***
Create a new web application firewall assessment.


#### Base Command

`cymulate-waf-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The ID of the template to run the WAF assessment with,. | Required | 
| sites | Websites to run the assessment on. Can be a single website URL or a list of URLs. | Required | 
| schedule | whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent.For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.WAF.id | String | Web application firewall assessment creation ID. | 
| Cymulate.WAF.success | Boolean | Web application firewall assessment creation success status. | 


#### Command Example
```!cymulate-waf-start template_id="5ee0726cef621bbc25251d7a" sites=" http://Google.com" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "WAF": {
            "Assessment": {
                "id": "id_456",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Starting WAF assessment:
>|id|success|
>|---|---|
>| id_456 | true |


### cymulate-waf-stop
***
Stop a running web application firewall assessment.


#### Base Command

`cymulate-waf-stop`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.WAF.data | String | Web application firewall assessment stopping data. | 
| Cymulate.WAF.success | Boolean | Web application firewall assessment stopping success status. | 


#### Command Example
```!cymulate-waf-stop```

#### Context Example
```json
{
    "Cymulate": {
        "WAF": {
            "Assessment": {
                "data": "no running attack",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Stopping WAF assessment:
>|data|success|
>|---|---|
>| no running attack | true |


### cymulate-waf-status
***
Get the web application firewall assessment status.


#### Base Command

`cymulate-waf-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | Assessment ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.WAF.id | String | Web application firewall assessment ID. | 
| Cymulate.WAF.success | Boolean | Whether the assessment was successful. | 
| Cymulate.WAF.inProgress | Boolean | Whether the assessment is in progress. | 
| Cymulate.WAF.progress | Number | Percentage of the progress of the assessment. | 
| Cymulate.EndpointSecurity.addresses | String | Addresses. | 


#### Command Example
```!cymulate-waf-status assessment_id="id_567"```

#### Context Example
```json
{
    "Cymulate": {
        "WAF": {
            "Assessment": {
                "addresses": null,
                "categories": [
                    "XML Injection",
                    "Command Injection",
                    "File Inclusion",
                    "XSS",
                    "XML Injection",
                    "SQL Injection"
                ],
                "id": "id_567",
                "inProgress": false,
                "progress": 0
            }
        }
    }
}
```

#### Human Readable Output

>### WAF assessment status:
>|categories|id|inProgress|progress|
>|---|---|---|---|
>| XML Injection,<br/>Command Injection,<br/>File Inclusion,<br/>XSS,<br/>XML Injection,<br/>SQL Injection | id_567 | false | 0 |


### cymulate-immediate-threat-start
***
Create a new immediate threats assessment.


#### Base Command

`cymulate-immediate-threat-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| browsing_address | Browsing address. | Optional | 
| mail_address | Agent email address. | Optional | 
| edr_address | EDR address. | Optional | 
| template_id | template ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.ImmediateThreats.id | String | Immediate threats assessment creation ID. | 


#### Command Example
```!cymulate-immediate-threat-start edr_address="LAPTOP-123" template_id="603270ce63aa15930631b938"```

#### Context Example
```json
{
    "Cymulate": {
        "ImmediateThreats": {
            "Assessment": {
                "id": [
                    "id_678"
                ],
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Starting immediate-threats assessment:
>|id|success|
>|---|---|
>| id_678 | true |


### cymulate-immediate-threat-stop
***
Stop a running immediate threats assessment.


#### Base Command

`cymulate-immediate-threat-stop`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.ImmediateThreats.data | String | Immediate threats assessment stopping data. | 


#### Command Example
```!cymulate-immediate-threat-stop```

#### Context Example
```json
{
    "Cymulate": {
        "ImmediateThreats": {
            "Assessment": {
                "data": "ok",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Stop immediate-threats assessment:
>|data|success|
>|---|---|
>| ok | true |


### cymulate-immediate-threat-status
***
Get immediate threats assessment status.


#### Base Command

`cymulate-immediate-threat-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | Assessment ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.ImmediateThreats.id | String | Web application firewall assessment ID. | 


#### Command Example
```!cymulate-immediate-threat-status assessment_id="id_789"```

#### Context Example
```json
{
    "Cymulate": {
        "ImmediateThreats": {
            "Assessment": {
                "addresses": null,
                "categories": [
                    "antivirus"
                ],
                "id": "id_789",
                "inProgress": false,
                "progress": 90
            }
        }
    }
}
```

#### Human Readable Output

>### Immediate-threats assessment status:
>|categories|id|inProgress|progress|
>|---|---|---|---|
>| antivirus | id_789 | false | 90 |


### cymulate-phishing-awareness-contacts-group-list
***
Get a list of contact groups.


#### Base Command

`cymulate-phishing-awareness-contacts-group-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Phishing.Groups.id | String | The ID of the phishing content group. | 
| Cymulate.Phishing.Groups.name | String | Name of the phishing content group. | 
| Cymulate.Phishing.Groups.client | String | The client of the phishing content group. | 
| Cymulate.Phishing.Groups.canDelete | Boolean | Whether this group can be deleted. | 


#### Command Example
```!cymulate-phishing-awareness-contacts-group-list```

#### Context Example
```json
{
    "Cymulate": {
        "Phishing": {
            "Groups": [
                {
                    "__v": 0,
                    "_id": "id_1",
                    "canDelete": true,
                    "client": "Cymulate",
                    "name": "aaaa"
                },
                {
                    "__v": 0,
                    "_id": "5d9afd80cb04cb43c1e946d1",
                    "canDelete": true,
                    "client": "Cymulate",
                    "name": "pruebas"
                },
                {
                    "__v": 0,
                    "_id": "5f747e7031628e1982bc8e70",
                    "canDelete": true,
                    "client": "Cymulate",
                    "name": "nurses "
                },
                {
                    "__v": 0,
                    "_id": "6034e7ac56f9436028882719",
                    "canDelete": true,
                    "client": "Cymulate",
                    "name": "qmasters_01"
                },
                {
                    "__v": 0,
                    "_id": "6034ee2056f943602888278c",
                    "canDelete": true,
                    "client": "Cymulate",
                    "name": "qmasters_02"
                },
                {
                    "__v": 0,
                    "_id": "6036799ac461036a89f9afdb",
                    "canDelete": true,
                    "client": "Cymulate",
                    "name": "qmasters_03"
                },
                {
                    "__v": 0,
                    "_id": "603ba6bdc3d4b76ab14dd91c",
                    "canDelete": true,
                    "client": "Cymulate",
                    "name": "new_group_01"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Phishing awareness contact groups:
>|__v|_id|canDelete|client|name|
>|---|---|---|---|---|
>| 0 | id_1 | true | Cymulate | aaaa |
>| 0 | 5d9afd80cb04cb43c1e946d1 | true | Cymulate | pruebas |
>| 0 | 5f747e7031628e1982bc8e70 | true | Cymulate | nurses  |
>| 0 | 6034e7ac56f9436028882719 | true | Cymulate | qmasters_01 |
>| 0 | 6034ee2056f943602888278c | true | Cymulate | qmasters_02 |
>| 0 | 6036799ac461036a89f9afdb | true | Cymulate | qmasters_03 |
>| 0 | 603ba6bdc3d4b76ab14dd91c | true | Cymulate | new_group_01 |


### cymulate-phishing-awareness-contacts-group-create
***
Create new contacts group.


#### Base Command

`cymulate-phishing-awareness-contacts-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the new group to create. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Phishing.Groups.success | Boolean | Whether the creation of the new group was successful. | 
| Cymulate.Phishing.Groups.id | String | The ID of the new phishing content group. | 


#### Command Example
```!cymulate-phishing-awareness-contacts-group-create group_name="Qmasters_group_01"```

#### Context Example
```json
{
    "Cymulate": {
        "Phishing": {
            "Groups": {
                "id": "id_0",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Phishing awareness contact group created:
>|id|success|
>|---|---|
>| id_0 | true |


### cymulate-phishing-awareness-contacts-get
***
Get contacts group using a group ID.


#### Base Command

`cymulate-phishing-awareness-contacts-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Group ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Phishing.Groups.id | String | The ID of the phishing content group. | 
| Cymulate.Phishing.Groups.name | String | Name of the phishing content group. | 
| Cymulate.Phishing.Groups.client | String | The client of the phishing content group. | 
| Cymulate.Phishing.Groups.canDelete | Boolean | Whether this group can be deleted. | 


#### Command Example
```!cymulate-phishing-awareness-contacts-get group_id="id_1"```

#### Context Example
```json
{
    "Cymulate": {
        "Phishing": {
            "Groups": [
                {
                    "_id": "id_1a",
                    "address": "jamesb@cymulate.com",
                    "color": "#ffbb00",
                    "firstName": "James",
                    "lastName": "Bond"
                },
                {
                    "_id": "id_a2",
                    "address": "Billg@cymulate.com",
                    "color": "#34a853",
                    "firstName": "Bill",
                    "lastName": "Gates"
                },
                {
                    "_id": "id_a3",
                    "address": "davidb@cymulate.com",
                    "color": "#00a1f1",
                    "firstName": "David ",
                    "lastName": "Ben-Gurion"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Phishing awareness contact groups:
>|_id|address|color|firstName|lastName|
>|---|---|---|---|---|
>| id_1a | jamesb@cymulate.com | #ffbb00 | James | Bond |
>| id_a2 | billg@cymulate.com | #34a853 | Bill | Gates |
>| id_a3 | davidb@cymulate.com | #00a1f1 | David  | Ben-Gurion |


### cymulate-lateral-movement-template-list
***
Retrieve lateral movement template list.


#### Base Command

`cymulate-lateral-movement-template-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.LateralMovement.Template.id | String | Template ID. | 


#### Command Example
```!cymulate-lateral-movement-template-list```

#### Context Example
```json
{
    "Cymulate": {
        "LateralMovement": {
            "Templates": [
                {
                    "_id": "5e2f0c1054d53d6b115eefa7",
                    "name": "SMB Pass The Hash"
                },
                {
                    "_id": "5e2f0c5f54d53d6b115ef0a1",
                    "name": "Kerberoasting and Cracking on DCOM and WMI"
                },
                {
                    "_id": "5e2f0c9754d53d6b115ef190",
                    "name": "LLMNR Poisoning on SMB"
                },
                {
                    "_id": "5e2f0d2c54d53d6b115ef345",
                    "name": "SMB And Credentials Harvesting"
                },
                {
                    "_id": "5e44020d3f46e106e9ec706c",
                    "name": "Prueba completa"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Lateral movement templates list:
>|_id|name|
>|---|---|
>| 5e2f0c1054d53d6b115eefa7 | SMB Pass The Hash |
>| 5e2f0c5f54d53d6b115ef0a1 | Kerberoasting and Cracking on DCOM and WMI |
>| 5e2f0c9754d53d6b115ef190 | LLMNR Poisoning on SMB |
>| 5e2f0d2c54d53d6b115ef345 | SMB And Credentials Harvesting |
>| 5e44020d3f46e106e9ec706c | Prueba completa |


### cymulate-lateral-movement-start
***
Create a new lateral movement assessment.


#### Base Command

`cymulate-lateral-movement-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_name | Agent name to run the assessment with. | Required | 
| template_id | The ID of the template to run the lateral movement with. | Required | 
| upload_to_cymulate | Whether to upload the result to Cymulate. Possible values are: true, false. Default is false. | Required | 
| schedule | Whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent.For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.LateralMovement.id | String | Lateral movement assessment creation ID. | 


#### Command Example
```!cymulate-lateral-movement-start agent_name="LAPTOP-123" template_id="5e41746171895006ef394607" upload_to_cymulate="false" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "LateralMovement": {
            "Assessment": {
                "id": "id_987",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Starting lateral movement assessment:
>|id|success|
>|---|---|
>| id_987 | true |


### cymulate-lateral-movement-stop
***
Stop a running lateral movement assessment.


#### Base Command

`cymulate-lateral-movement-stop`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.LateralMovement.data | String | Lateral movement assessment stopping data. | 
| Cymulate.LateralMovement.status | Boolean | Lateral movement assessment stopping success status. | 


#### Command Example
```!cymulate-lateral-movement-stop```

#### Context Example
```json
{
    "Cymulate": {
        "LateralMovement": {
            "Assessment": {
                "data": "no running attacks",
                "success": true
            }
        }
    }
}
```

#### Human Readable Output

>### Stopping lateral movement assessment:
>|data|success|
>|---|---|
>| no running attacks | true |


### cymulate-lateral-movement-status
***
Get lateral movement assessment status.


#### Base Command

`cymulate-lateral-movement-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assessment_id | Assessment ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.LateralMovement.id | String | Lateral movement assessment ID. | 


#### Command Example
```!cymulate-lateral-movement-status assessment_id="id_876"```

#### Context Example
```json
{
    "Cymulate": {
        "LateralMovement": {
            "Assessment": {
                "addresses": null,
                "categories": null,
                "id": "id_876",
                "inProgress": false,
                "progress": null
            }
        }
    }
}
```

#### Human Readable Output

>### Lateral movement assessment status:
>|id|inProgress|
>|---|---|
>| id_876 | false |


### cymulate-agent-list
***
Retrieve all agents.


#### Base Command

`cymulate-agent-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Agent.agentAddress | String | The agent's address. | 
| Cymulate.Agent.addressMethod | String | The agent's methods. | 


#### Command Example
```!cymulate-agent-list```

#### Context Example
```json
{
    "Cymulate": {
        "Agent": [
            {
                "agentAddress": "James ",
                "agentMethod": "http",
                "agentName": "James"
            },
            {
                "agentAddress": "Bill-MacBook-Pro ",
                "agentMethod": "http",
                "agentName": "Bill-MacBook-Pro"
            }
        ]
    }
}
```

#### Human Readable Output

>### Agents list:
>|agentAddress|agentMethod|agentName|
>|---|---|---|
>| James  | http | James |
>| Bill-MacBook-Pro  | http | Bill-MacBook-Pro |


### cymulate-simulations-list
***
Retrieve a list of all simulations by ID.


#### Base Command

`cymulate-simulations-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| module | Module to retrieve events to. Possible values are: web-gateway, exfiltration, email-gateway, endpoint-security, waf, kill-chain, immediate-threats, phishing-awareness, lateral-movement. | Required | 
| attack_id | Attack ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Simulations.Attack_Type | String | Attack payload | 
| Cymulate.Simulations.Classification | String | Attack classification. | 
| Cymulate.Simulations.Content_Type | String | Content type. | 
| Cymulate.Simulations.Module | String | Event's module. | 
| Cymulate.Simulations.Phrase | String | Attack description. | 
| Cymulate.Simulations.Phrase_Title | String | Attack name. | 
| Cymulate.Simulations.Status | String | Attack status | 
| Cymulate.Simulations.PrevStatus | String | Attack Previous status | 
| Cymulate.Simulations.Risk | String | Attack risk level. | 
| Cymulate.Simulations.Source | String | Attack Source | 
| Cymulate.Simulations.User | String | User committed the attack ot was attacked. | 
| Cymulate.Simulations.Attack_Vector | String | Attack vector | 
| Cymulate.Simulations.Source_Email_Address | String | Source email address. | 
| Cymulate.Simulations.Md5 | String | MD5 attached to the attack. | 
| Cymulate.Simulations.Sha256 | String | Sha256 attached to the attack. | 
| Cymulate.Simulations.Sha1 | String | Sha1 attached to the attack. | 
| Cymulate.Simulations.Mitigation | String | Mitigation details. | 
| Cymulate.Simulations.Mitigation_Details | String | Mitigation details. | 
| Cymulate.Simulations.Description | String | Attack description | 
| Cymulate.Simulations.Id | String | Attack ID. | 


#### Command Example
```!cymulate-simulations-list module="waf" attack_id="id_001"```

#### Context Example
```json
{
    "Cymulate": {
        "Simulations": {
            "Action": " http://Google.com/",
            "Category": "SQL Injection",
            "Database": "DB Agnostic",
            "Display_Url": " http://Google.com/",
            "FullRequest": "N/A",
            "Id": "id_001",
            "Input": "password",
            "Method": "post",
            "Mitigation": "Create a WAF Security rule to block incoming requests that contains. Validate that the specific input url is protected with the MSSQL Blind signature pack (SQL Injection)",
            "Module": "Web Application Firewall",
            "Payload": "This is a payload",
            "Platform": "OS Agnostic",
            "PrevStatus": "blocked",
            "Risk": "high",
            "Source": " http://Google.com",
            "Status": "blocked",
            "SubCategoryType": "MSSQL Blind",
            "Timestamp": "2021-02-28 16:33:41",
            "Url": " http://Google.com/",
            "date": "2021-02-28T14:33:41.559Z"
        }
    }
}
```

#### Human Readable Output

>### Displaying 20/193 simulations:
>|Action|Category|Database|Display_Url|FullRequest|Id|Input|Method|Mitigation|Module|Payload|Platform|PrevStatus|Risk|Source|Status|SubCategoryType|Timestamp|Url|date|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| http://Google.com/signup | SQL Injection | DB Agnostic | http://Google.com/signup | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains. Validate that the specific input/url is protected with the Oracle SQL Injection signature pack (SQL Injection) | Web Application Firewall | AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM (SELECT DISTINCT(table_name), ROWNUM AS LIMIT FROM sys.all_tables) WHERE LIMIT=3)) AND 'i'='i | OS Agnostic | blocked | high | http://Google.com | blocked | Oracle SQL Injection | 2021-02-28 16:33:41 | http://Google.com/signup | 2021-02-28T14:33:41.475Z |
>| http://Google.com/team/dudi | SQL Injection | DB Agnostic | http://Google.com/team/dudi | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains.. The rule could be a Regular expression that needs to be implemented or an update of your WAF.Validate that the specific input url is protected with the Generic Blind Injection signature pack (SQL Injection) | Web Application Firewall | 1) or benchmark(10000000,MD5(1))# | OS Agnostic | blocked | high | http://Google.com | blocked | Generic Blind Injection | 2021-02-28 16:33:41 | http://Google.com/team/dudi | 2021-02-28T14:33:41.476Z |
>| http://Google.com/ | SQL Injection | DB Agnostic | http://Google.com/ | N/A | id_001 | tel | post | Create a WAF Security rule to block incoming requests that contains:1.The rule could be a Regular expression that needs to be implemented or an update of your WAF.Validate that the specific input/url is protected with the General SQL Injection signature pack (SQL Injection) | Web Application Firewall | 1' and non_existant_table = '1 | OS Agnostic | blocked | high | http://Google.com | blocked | General SQL Injection | 2021-02-28 16:33:41 | http://Google.com/ | 2021-02-28T14:33:41.478Z |
>| http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | SQL Injection | DB Agnostic | http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains:..The rule could be a Regular expression that needs to be implemented or an update of your WAF.Validate that the specific input/url is protected with the Passive SQL Injection signature pack (SQL Injection) | Web Application Firewall | ' or 1=1 / | OS Agnostic | blocked | high | http://Google.com | blocked | Passive SQL Injection | 2021-02-28 16:33:41 | http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | 2021-02-28T14:33:41.478Z |
>| http://Google.com/contact | SQL Injection | DB Agnostic | http://Google.com/contact | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains..The rule could be a Regular expression that needs to be implemented or an update of your WAF.Validate that the specific input/url is protected with the Passive SQL Injection signature pack (SQL Injection) | Web Application Firewall | ' group by userid having 1=1-- | OS Agnostic | blocked | high | http://Google.com | blocked | Passive SQL Injection | 2021-02-28 16:33:41 | http://Google.com/contact | 2021-02-28T14:33:41.476Z |
>| http://Google.com/ | SQL Injection | DB Agnostic | http://Google.com/ | N/A | id_001 | tel | post | Create a WAF Security rule to block incoming requests that contains.The rule could be a Regular expression that needs to be implemented or an update of your WAF.Validate that the specific input/url is protected with the MSSQL Injection signature pack (SQL Injection) | Web Application Firewall | ) waitfor delay '0:0:20' | OS Agnostic | blocked | high | http://Google.com | blocked | MSSQL Injection | 2021-02-28 16:33:41 | http://Google.com/ | 2021-02-28T14:33:41.479Z |
>| http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | SQL Injection | DB Agnostic | http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains.Validate that the specific input/url is protected with the Passive SQL Injection signature pack (SQL Injection) | Web Application Firewall | ' or 1=1-- | OS Agnostic | blocked | high | http://Google.com | blocked | Passive SQL Injection | 2021-02-28 16:33:41 | http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | 2021-02-28T14:33:41.481Z |
>| http://Google.com/ | SQL Injection | DB Agnostic | http://Google.com/ | N/A | id_001 | hidden | post | Create a WAF Security rule to block incoming requests that contains:.Validate that the specific input/url is protected with the Passive SQL Injection signature pack (SQL Injection) | Web Application Firewall | ' OR 'something' like 'some%' | OS Agnostic | blocked | high | http://Google.com | blocked | Passive SQL Injection | 2021-02-28 16:33:41 | http://Google.com/ | 2021-02-28T14:33:41.480Z |
>| http://Google.com/team/ruba | SQL Injection | DB Agnostic | http://Google.com/team/ruba | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains.The rule could be a Regular expression that needs to be implemented or an update of your WAF.Validate that the specific input/url is protected with the Passive SQL Injection signature pack (SQL Injection) | Web Application Firewall | ' union select from users where login = char(114,111,111,116); | OS Agnostic | blocked | high | http://Google.com | blocked | Passive SQL Injection | 2021-02-28 16:33:41 | http://Google.com/team/ruba | 2021-02-28T14:33:41.481Z |
>| http://Google.com/team/ruba | SQL Injection | DB Agnostic | http://Google.com/team/ruba | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains. The rule could be a Regular expression that needs to be implemented or an update of your WAF.Validate that the specific input/url is protected with the General SQL Injection signature pack (SQL Injection) | Web Application Firewall | ' AND 1=utl_inaddr.get_host_address((SELECT SYS.DATABASE_NAME FROM DUAL)) AND 'i'='i | OS Agnostic | blocked | high | http://Google.com | blocked | General SQL Injection | 2021-02-28 16:33:41 | http://Google.com/team/ruba | 2021-02-28T14:33:41.479Z |
>| http://Google.com/contact | SQL Injection | DB Agnostic | http://Google.com/contact | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains.Validate that the specific input/url is protected with the Generic Blind Injection signature pack (SQL Injection) | Web Application Firewall | ;waitfor delay '0:0:__TIME__'-- | OS Agnostic | blocked | high | http://Google.com | blocked | Generic Blind Injection | 2021-02-28 16:33:41 | http://Google.com/contact | 2021-02-28T14:33:41.480Z |
>| http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | SQL Injection | DB Agnostic | http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains. The rule could be a Regular expression that needs to be implemented or an update of your WAF.Validate that the specific input/url is protected with the MSSQL Injection signature pack (SQL Injection) | Web Application Firewall | waitfor delay '0:0:20' / | OS Agnostic | blocked | high | http://Google.com | blocked | MSSQL Injection | 2021-02-28 16:33:41 | http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | 2021-02-28T14:33:41.481Z |
>| http://Google.com/team/dudi | SQL Injection | DB Agnostic | http://Google.com/team/dudi | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains:.Validate that the specific input/url is protected with the Mysql Injection signature pack (SQL Injection) | Web Application Firewall | 1or1=1 | OS Agnostic | blocked | high | http://Google.com | blocked | Mysql Injection | 2021-02-28 16:33:41 | http://Google.com/team/dudi | 2021-02-28T14:33:41.483Z |
>| http://Google.com/team/dudi | SQL Injection | DB Agnostic | http://Google.com/team/dudi | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains.Validate that the specific input/url is protected with the Generic Blind Injection signature pack (SQL Injection) | Web Application Firewall | ) or sleep(__TIME__)=' | OS Agnostic | blocked | high | http://Google.com | blocked | Generic Blind Injection | 2021-02-28 16:33:41 | http://Google.com/team/dudi | 2021-02-28T14:33:41.483Z |
>| http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | SQL Injection | DB Agnostic | http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains.Validate that the specific input/url is protected with the Passive SQL Injection signature pack (SQL Injection) | Web Application Firewall |  @var select @var as var into temp end -- | OS Agnostic | blocked | high | http://Google.com | blocked | Passive SQL Injection | 2021-02-28 16:33:41 | http://Google.com/team/%d7%94%d7%9e%d7%a8%d7%a4%d7%90%d7%95%d7%aa-%d7%a9%d7%9c%d7%a0%d7%95 | 2021-02-28T14:33:41.485Z |
>| http://Google.com/team/ruba | SQL Injection | DB Agnostic | http://Google.com/team/ruba | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains.Validate that the specific input/url is protected with the Oracle SQL Injection signature pack (SQL Injection) | Web Application Firewall | AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(granted_role) FROM (SELECT DISTINCT(granted_role), ROWNUM AS LIMIT FROM dba_role_privs WHERE GRANTEE=SYS.LOGINUSER) WHERE LIMIT=1)) AND 'i'='i | OS Agnostic | blocked | high | http://Google.com | blocked | Oracle SQL Injection | 2021-02-28 16:33:41 | http://Google.com/team/ruba | 2021-02-28T14:33:41.482Z |
>| http://Google.com/signup | SQL Injection | DB Agnostic | http://Google.com/signup | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains.Validate that the specific input/url is protected with the Mysql Injection signature pack (SQL Injection) | Web Application Firewall | create table myfile (input TEXT); load data infile filepath into table myfile | OS Agnostic | blocked | high | http://Google.com | blocked | Mysql Injection | 2021-02-28 16:33:41 | http://Google.com/signup | 2021-02-28T14:33:41.484Z |
>| http://Google.com/contact | SQL Injection | DB Agnostic | http://Google.com/contact | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains. The rule could be a Regular expression that needs to be implemented or an update of your WAF.Validate that the specific input/url is protected with the MSSQL Injection signature pack (SQL Injection) | Web Application Firewall | and 0=benchmark | OS Agnostic | blocked | high | http://Google.com | blocked | MSSQL Injection | 2021-02-28 16:33:41 | http://Google.com/contact | 2021-02-28T14:33:41.486Z |
>| http://Google.com/ | SQL Injection | DB Agnostic | http://Google.com/ | N/A | id_001 | tel | post | Create a WAF Security rule to block incoming requests that contains.Validate that the specific input/url is protected with the MSSQL Injection signature pack (SQL Injection) | Web Application Firewall | ; exec master..xp_cmdshell 'ping 10.10.1.2'-- | OS Agnostic | blocked | high | http://Google.com | blocked | MSSQL Injection | 2021-02-28 16:33:41 | http://Google.com/ | 2021-02-28T14:33:41.485Z |
>| http://Google.com/signup | SQL Injection | DB Agnostic | http://Google.com/signup | N/A | id_001 | password | post | Create a WAF Security rule to block incoming requests that contains.Validate that the specific input/url is protected with the MSSQL Injection signature pack (SQL Injection) | Web Application Firewall | insert into mysql.user (user, host, password) values ('name', 'localhost', password('pass123')) -- | OS Agnostic | N/A | high | http://Google.com | blocked | MSSQL Injection | 2021-02-28 16:33:41 | http://Google.com/signup | 2021-02-28T14:33:41.487Z |


### cymulate-simulations-id-list
***
Retrieve a list of all simulations IDs.


#### Base Command

`cymulate-simulations-id-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| module | Module to retrieve simulations IDs to. Possible values are: web-gateway, exfiltration, email-gateway, endpoint-security, waf, kill-chain, immediate-threats, phishing-awareness, lateral-movement. | Required | 
| from_date | From which date to fetch data. format: year-month-day. For example: March 1st 2021 should be written: 2021-03-1. . | Required | 
| to_date | End date to fetch data. If no argument is given, default is now. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Simulations.ID | String | Attack ID. | 
| Cymulate.Simulations.Timestamp | String | Attack timestamp | 
| Cymulate.Simulations.Agent | String | Agent connected to the attack. | 
| Cymulate.Simulations.Template | String | Attack template. | 


#### Command Example
```!cymulate-simulations-id-list module="kill-chain" from_date="2021-01-01"```

#### Context Example
```json
{
    "Cymulate": {
        "Simulations": {
            "Agent": "",
            "ID": "id_002",
            "Template": "fdsf",
            "Timestamp": "2021-01-20 18:08:09.565000"
        }
    }
}
```

#### Human Readable Output

>### Displaying 6/6 Attack IDs:
>|Agent|ID|Template|Timestamp|
>|---|---|---|---|
>| LAPTOP-123 | 603cbedea873f53d0c81a734 | Cobalt Group | 2021-03-01 10:15:58.230000 |
>| LAPTOP-123 | 6037d6c1c3d4b76ab14cc40d | Cobalt Group | 2021-02-25 16:56:33.871000 |
>| info@cymulate.com | 6034e062b862ca5d6ad4af79 | Cobalt Group | 2021-02-23 11:00:50.988000 |
>|  | 60087ac9d60eab3c5222c095 | fdsf | 2021-01-20 18:47:37.452000 |
>|  | 60087a176b52e55f393cf584 | fdsf | 2021-01-20 18:44:39.469000 |
>|  | id_002 | fdsf | 2021-01-20 18:08:09.565000 |
