Multi-Vector Cyber Attack, Breach and Attack Simulation.
This integration was integrated and tested with API version 1 of cymulate

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure cymulate_v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API token |  | True |
| Base URL |  | False |
| Fetch incidents |  | False |
| Fetch category | Choose one or more categories to fetch. | False |
| Incident type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Max Fetch | Maximal number of incidents to fetch. Max value can be no grater than 35. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.


## Fetch Incidents command
Retrieves new incidents every interval (default is 1 minute).
The fetch incident command will retrieve incidents from all selected modules chosen in the configuration page by the user.
The next run will be calculated by the latest timestamp of all modules, to avoid duplications.
NOTE: We fetch only one module per fetch call.


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
                    "id": "5df0e79b85a00138dc648e75",
                    "name": "Cymulate Best Practice"
                },
                {
                    "id": "5df0e7d585a00138dc648e8f",
                    "name": "Cloud Services"
                },
                {
                    "id": "5df0e80885a00138dc648ea7",
                    "name": "Network Protocols"
                },
                {
                    "id": "5df0e82e85a00138dc648ebb",
                    "name": "Email"
                },
                {
                    "id": "5df25b3696fa2af420a379b9",
                    "name": "Physical"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Exfiltration templates list:
>|id|name|
>|---|---|
>| 5df0e79b85a00138dc648e75 | Cymulate Best Practice |
>| 5df0e7d585a00138dc648e8f | Cloud Services |
>| 5df0e80885a00138dc648ea7 | Network Protocols |
>| 5df0e82e85a00138dc648ebb | Email |
>| 5df25b3696fa2af420a379b9 | Physical |


### cymulate-exfiltration-start
***
Create a new exfiltration assessment.


#### Base Command

`cymulate-exfiltration-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The ID of the template to run the exfiltration Assessment with. Can be retrieved using Cymulate's UI, or using cymulate-exfiltration-template-list command. | Required | 
| agent_name | agent name to run simulation attacks. | Required | 
| schedule | whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent. For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 
| agent_profile_name | agent profile name to run simulation attacks. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.Exfiltration.id | String | New exfiltration assessment creation ID. | 
| Cymulate.Exfiltration.success | Boolean | New exfiltration assessment creation success status. | 


#### Command Example
```!cymulate-exfiltration-start template_id="5df0e79b85a00138dc648e75" agent_name="Cymulate_agent" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "Exfiltration": {
            "id": "id_1",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Starting exfiltration assessment:
>|id|success|
>|---|---|
>| id_1 | true |


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
            "data": "ok",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Stopping exfiltration assessment:
>|data|success|
>|---|---|
>| ok | true |


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
```!cymulate-exfiltration-status assessment_id="id_2"```

#### Context Example
```json
{
    "Cymulate": {
        "Exfiltration": {
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
            "id": "id_2",
            "inProgress": false,
            "progress": 0
        }
    }
}
```

#### Human Readable Output

>### Exfiltration assessment status:
>|categories|id|inProgress|progress|
>|---|---|---|---|
>| http,<br/>https,<br/>dns,<br/>dns-tunneling,<br/>icmp,<br/>outlook,<br/>device,<br/>telnet,<br/>sftp,<br/>slack,<br/>googledrive,<br/>onedrive,<br/>port_scanning,<br/>msteams,<br/>gmail,<br/>gitlab,<br/>azure_blob,<br/>aws_s3_bucket,<br/>github,<br/>googlestorage,<br/>browsinghttps,<br/>browsinghttp | id_2 | false | 0 |


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
                    "id": "5c6920853659191ccf6858fc",
                    "name": "free assessment"
                },
                {
                    "id": "5c6920853659191ccf6858fb",
                    "name": "cymulate best practice"
                },
                {
                    "id": "5db5ab6e79a0bf2feedaf9a7",
                    "name": "cymulate best practice - high risk"
                },
                {
                    "id": "5c6968e43659191ccf685929",
                    "name": "office payloads"
                },
                {
                    "id": "5c6968ec3659191ccf68592a",
                    "name": "executables payloads"
                },
                {
                    "id": "5c73b2ce3febfc300976c6e3",
                    "name": "exploits"
                },
                {
                    "id": "5c7f96963febfc300976c7be",
                    "name": "malwares"
                },
                {
                    "id": "5c7f977bc9545f79ea8b03c0",
                    "name": "ransomwares"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Email gateway templates list:
>|id|name|
>|---|---|
>| 5c6920853659191ccf6858fc | free assessment |
>| 5c6920853659191ccf6858fb | cymulate best practice |
>| 5db5ab6e79a0bf2feedaf9a7 | cymulate best practice - high risk |
>| 5c6968e43659191ccf685929 | office payloads |
>| 5c6968ec3659191ccf68592a | executables payloads |
>| 5c73b2ce3febfc300976c6e3 | exploits |
>| 5c7f96963febfc300976c7be | malwares |
>| 5c7f977bc9545f79ea8b03c0 | ransomwares |


### cymulate-email-gateway-start
***
Create a new email gateway assessment.


#### Base Command

`cymulate-email-gateway-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The ID of the template to run the email gateway assessment with. Can be retrieved using Cymulate's UI, or using cymulate-email-gateway-template-list command. | Required | 
| agent_email | agent email. | Required | 
| schedule | whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent. For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EmailGateway.id | String | New email gateway assessment creation ID. | 
| Cymulate.EmailGateway.success | Boolean | New email gateway assessment creation success status. | 


#### Command Example
```!cymulate-email-gateway-start template_id="5c6920853659191ccf6858fc" agent_email="test@cymulate.com" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "EmailGateway": {
            "id": "id_3",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Starting email gateway assessment:
>|id|success|
>|---|---|
>| id_3 | true |


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
            "data": "ok",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Stopping email gateway assessment:
>|data|success|
>|---|---|
>| ok | true |


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
| Cymulate.EmailGateway.addresses | String | Addresses connected to the assessment. | 


#### Command Example
```!cymulate-email-gateway-status assessment_id="id_4"```

#### Context Example
```json
{
    "Cymulate": {
        "EmailGateway": {
            "addresses": [
                "test@cymulate.com"
            ],
            "categories": [
                "worm"
            ],
            "id": "id_4",
            "inProgress": false,
            "progress": 0
        }
    }
}
```

#### Human Readable Output

>### Email gateway assessment status:
>|addresses|categories|id|inProgress|progress|
>|---|---|---|---|---|
>| test@cymulate.com | worm | id_4 | false | 0 |


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
                    "id": "5c87a26f548a3c7c4c184a5e",
                    "name": "Free Assessment"
                },
                {
                    "id": "5c97a50c5727c58a295d0459",
                    "name": "Cymulate Best Practice"
                },
                {
                    "id": "5e98461d312a740ee4839700",
                    "name": "DLL Side loading"
                },
                {
                    "id": "5c87a314548a3c7c4c184a5f",
                    "name": "Cymulate Behavior-based"
                },
                {
                    "id": "5c87a314548a3c7c4c184a60",
                    "name": "Cymulate Signature-based"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Endpoint security templates list:
>|id|name|
>|---|---|
>| 5c87a26f548a3c7c4c184a5e | Free Assessment |
>| 5c97a50c5727c58a295d0459 | Cymulate Best Practice |
>| 5e98461d312a740ee4839700 | DLL Side loading |
>| 5c87a314548a3c7c4c184a5f | Cymulate Behavior-based |
>| 5c87a314548a3c7c4c184a60 | Cymulate Signature-based |


### cymulate-endpoint-security-start
***
Create a new endpoint security assessment.


#### Base Command

`cymulate-endpoint-security-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The ID of the template to run the endpoint security assessment with. Can be retrieved using Cymulate's UI, or using cymulate-endpoint-security-template-list command. | Required | 
| agent_name | agent name. | Required | 
| schedule | whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent. For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 
| agent_profile_name | Agent profile name. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.EndpointSecurity.id | String | New endpoint security assessment creation ID. | 
| Cymulate.EndpointSecurity.success | Boolean | New endpoint security assessment creation success status. | 


#### Command Example
```!cymulate-endpoint-security-start template_id="5e98461d312a740ee4839700" agent_name="Cymulate_agent" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "EndpointSecurity": {
            "id": "id_5",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Starting endpoint security assessment:
>|id|success|
>|---|---|
>| id_5 | true |


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
            "data": "ok",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Stopping endpoint security assessment:
>|data|success|
>|---|---|
>| ok | true |


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
| Cymulate.EndpointSecurity.inProgress | Boolean | Whether the assessment is in progress. | 
| Cymulate.EndpointSecurity.progress | Number | Percentage of the progress of the assessment. | 
| Cymulate.EndpointSecurity.categories | String | Assessment categories. | 


#### Command Example
```!cymulate-endpoint-security-status assessment_id="id_6"```

#### Context Example
```json
{
    "Cymulate": {
        "EndpointSecurity": {
            "categories": [
                "ransomware"
            ],
            "id": "id_6",
            "inProgress": true,
            "progress": 90
        }
    }
}
```

#### Human Readable Output

>### Endpoint security assessment status:
>|categories|id|inProgress|progress|
>|---|---|---|---|
>| ransomware | id_6 | false | 0 |


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
                    "id": "5edf7ddfef621bbc252498f3",
                    "name": "free assessment"
                },
                {
                    "id": "5edf7547ef621bbc25248d97",
                    "name": "Cymulate Best Practice"
                },
                {
                    "id": "5ee0726cef621bbc25251d7a",
                    "name": "SQL Injection"
                },
                {
                    "id": "5ee0726cef621bbc25251d7d",
                    "name": "XSS"
                },
                {
                    "id": "5eea1fb754b285889325b818",
                    "name": "Command Injection"
                },
                {
                    "id": "5eea1fb754b285889325b81b",
                    "name": "File Inclusion"
                },
                {
                    "id": "5fb65327f6ce656dbc7f9cf1",
                    "name": "SSRF"
                },
                {
                    "id": "600d258cbd15e73c5882b306",
                    "name": "david test"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### WAF templates list:
>|id|name|
>|---|---|
>| 5edf7ddfef621bbc252498f3 | free assessment |
>| 5edf7547ef621bbc25248d97 | Cymulate Best Practice |
>| 5ee0726cef621bbc25251d7a | SQL Injection |
>| 5ee0726cef621bbc25251d7d | XSS |
>| 5eea1fb754b285889325b818 | Command Injection |
>| 5eea1fb754b285889325b81b | File Inclusion |
>| 5fb65327f6ce656dbc7f9cf1 | SSRF |
>| 600d258cbd15e73c5882b306 | david test |


### cymulate-waf-start
***
Create a new web application firewall assessment.


#### Base Command

`cymulate-waf-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The ID of the template to run the WAF assessment with. Can be retrieved using Cymulate's UI, or using cymulate-waf-template-list command. | Required | 
| sites | Websites to run the assessment on. Can be a single website URL or a list of URLs. | Required | 
| schedule | whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent. For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.WAF.id | String | Web application firewall assessment creation ID. | 
| Cymulate.WAF.success | Boolean | Web application firewall assessment creation success status. | 


#### Command Example
```!cymulate-waf-start template_id="5ee0726cef621bbc25251d7a" sites="http://cymulatelabs.com" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "WAF": {
            "id": "604630cbb9eb930a0fa86ab5",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Starting WAF assessment:
>|id|success|
>|---|---|
>| 604630cbb9eb930a0fa86ab5 | true |


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
            "data": "no running attack",
            "success": true
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
| Cymulate.WAF.inProgress | Boolean | Whether the assessment is in progress. | 
| Cymulate.WAF.progress | Number | Percentage of the progress of the assessment. | 
| Cymulate.WAF.categories | String | Assessment categories. | 


#### Command Example
```!cymulate-waf-status assessment_id="5ff31ef451647c20338bd235"```

#### Context Example
```json
{
    "Cymulate": {
        "WAF": {
            "categories": [
                "XML Injection",
                "Command Injection",
                "File Inclusion",
                "XSS",
                "XML Injection",
                "SQL Injection"
            ],
            "id": "5ff31ef451647c20338bd235",
            "inProgress": false,
            "progress": 0
        }
    }
}
```

#### Human Readable Output

>### WAF assessment status:
>|categories|id|inProgress|progress|
>|---|---|---|---|
>| XML Injection,<br/>Command Injection,<br/>File Inclusion,<br/>XSS,<br/>XML Injection,<br/>SQL Injection | 5ff31ef451647c20338bd235 | false | 0 |


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
| template_id | The ID of the template to run the immediate threat assessment with. Can be retrieved using Cymulate's UI. | Required | 
| browsing_address_profile_name | Browsing Agent profile name to run the assessment with. | Optional |
| edr_address_profile_name | EDR Agent profile name to run the assessment with. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.ImmediateThreats.id | String | Immediate threats assessment creation ID. | 
| Cymulate.ImmediateThreats.success | String | New exfiltration assessment creation success status. | 


#### Command Example
```!cymulate-immediate-threat-start edr_address="Cymulate_agent" template_id="603270ce63aa15930631b938"```

#### Context Example
```json
{
    "Cymulate": {
        "ImmediateThreats": {
            "id": [
                "id_7"
            ],
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Starting immediate-threats assessment:
>|id|success|
>|---|---|
>| id_7 | true |


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
| Cymulate.ImmediateThreats.success | String | Immediate threats assessment stopping success status. | 


#### Command Example
```!cymulate-immediate-threat-stop```

#### Context Example
```json
{
    "Cymulate": {
        "ImmediateThreats": {
            "data": "ok",
            "success": true
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
| Cymulate.ImmediateThreats.categories | String | Assessment categories. | 
| Cymulate.ImmediateThreats.inProgress | Boolean | Whether the assessment is in progress. | 
| Cymulate.ImmediateThreats.progress | Number | Percentage of the progress of the assessment. | 


#### Command Example
```!cymulate-immediate-threat-status assessment_id="id_8"```

#### Context Example
```json
{
    "Cymulate": {
        "ImmediateThreats": {
            "categories": [
                "antivirus"
            ],
            "id": "id_8",
            "inProgress": true,
            "progress": 90
        }
    }
}
```

#### Human Readable Output

>### Immediate-threats assessment status:
>|categories|id|inProgress|progress|
>|---|---|---|---|
>| antivirus | id_8 | true | 90 |


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
                    "canDelete": true,
                    "client": "Cymulate",
                    "id": "id_a",
                    "name": "qmasters_01"
                },
                {
                    "__v": 0,
                    "canDelete": true,
                    "client": "Cymulate",
                    "id": "id_b",
                    "name": "qmasters_02"
                },
                {
                    "__v": 0,
                    "canDelete": true,
                    "client": "Cymulate",
                    "id": "id_c",
                    "name": "qmasters_03"
                },
                {
                    "__v": 0,
                    "canDelete": true,
                    "client": "Cymulate",
                    "id": "id_d",
                    "name": "new_group_01"
                },
                {
                    "__v": 0,
                    "canDelete": true,
                    "client": "Cymulate",
                    "id": "id_e",
                    "name": "test_group_02"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Phishing awareness contact groups:
>|__v|canDelete|client|id|name|
>|---|---|---|---|---|
>| 0 | true | Cymulate | id_a | qmasters_01 |
>| 0 | true | Cymulate | id_b | qmasters_02 |
>| 0 | true | Cymulate | id_c | qmasters_03 |
>| 0 | true | Cymulate | id_d | new_group_01 |
>| 0 | true | Cymulate | id_e | test_group_02 |


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
```!cymulate-phishing-awareness-contacts-group-create group_name="test_group_01"```

#### Context Example
```json
{
    "Cymulate": {
        "Phishing": {
            "Groups": {
                "id": "id_9",
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
>| id_9 | true |


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
```!cymulate-phishing-awareness-contacts-get group_id="id_abcd"```

#### Context Example
```json
{
    "Cymulate": {
        "Phishing": {
            "Groups": [
                {
                    "address": "jamesb@cymulate.com",
                    "color": "#ffbb00",
                    "firstName": "James",
                    "id": "id_1a",
                    "lastName": "Bond"
                },
                {
                    "address": "Billg@cymulate.com",
                    "color": "#34a853",
                    "firstName": "Bill",
                    "id": "id_a2",
                    "lastName": "Gates"
                },
                {
                    "address": "davidb@cymulate.com",
                    "color": "#00a1f1",
                    "firstName": "David ",
                    "id": "id_a3",
                    "lastName": "Ben-Gurion"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Phishing awareness contact groups:
>|address|color|firstName|id|lastName|
>|---|---|---|---|---|
>| jamesb@cymulate.com | #ffbb00 | James | id_1a | Bond |
>| Billg@cymulate.com | #34a853 | Bill | id_a2 | Gates |
>| davidb@cymulate.com | #00a1f1 | David  | id_a3 | Ben-Gurion |


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
| Cymulate.LateralMovement.Template.name | String | Template name. | 


#### Command Example
```!cymulate-lateral-movement-template-list```

#### Context Example
```json
{
    "Cymulate": {
        "LateralMovement": {
            "Templates": [
                {
                    "id": "5e2f0c1054d53d6b115eefa7",
                    "name": "SMB Pass The Hash"
                },
                {
                    "id": "5e2f0c5f54d53d6b115ef0a1",
                    "name": "Kerberoasting and Cracking on DCOM and WMI"
                },
                {
                    "id": "5e2f0c9754d53d6b115ef190",
                    "name": "LLMNR Poisoning on SMB"
                },
                {
                    "id": "5e2f0d2c54d53d6b115ef345",
                    "name": "SMB And Credentials Harvesting"
                },
                {
                    "id": "5e41746171895006ef394607",
                    "name": "test1"
                },
                {
                    "id": "5e44020d3f46e106e9ec706c",
                    "name": "Prueba completa"
                },
                {
                    "id": "5e4a5792b1bdb606ed1f9407",
                    "name": "lab1"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Lateral movement templates list:
>|id|name|
>|---|---|
>| 5e2f0c1054d53d6b115eefa7 | SMB Pass The Hash |
>| 5e2f0c5f54d53d6b115ef0a1 | Kerberoasting and Cracking on DCOM and WMI |
>| 5e2f0c9754d53d6b115ef190 | LLMNR Poisoning on SMB |
>| 5e2f0d2c54d53d6b115ef345 | SMB And Credentials Harvesting |
>| 5e41746171895006ef394607 | test1 |
>| 5e44020d3f46e106e9ec706c | Prueba completa |
>| 5e4a5792b1bdb606ed1f9407 | lab1 |


### cymulate-lateral-movement-start
***
Create a new lateral movement assessment.


#### Base Command

`cymulate-lateral-movement-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_name | Agent name to run the assessment with. | Required | 
| template_id | The ID of the template to run the lateral movement with. Can be retrieved using Cymulate's UI, or using cymulate-lateral-movement-template-list command. | Required | 
| upload_to_cymulate | Whether to upload the result to Cymulate. Possible values are: true, false. Default is false. | Required | 
| schedule | Whether to schedule the automated assessment periodically. Possible values are: true, false. | Required | 
| schedule_loop | Loop size of the scheduled agent. For example: to run the agent only once, use the value 'one-time'. Possible values are: one-time, daily, weekly, monthly. | Required | 
| agent_profile_name | Agent profile name to run the assessment with. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cymulate.LateralMovement.id | String | Lateral movement assessment creation ID. | 
| Cymulate.LateralMovement.success | Boolean | New exfiltration assessment creation success status. | 


#### Command Example
```!cymulate-lateral-movement-start agent_name="Cymulate_agent" template_id="5e41746171895006ef394607" upload_to_cymulate="false" schedule="false" schedule_loop="one-time"```

#### Context Example
```json
{
    "Cymulate": {
        "LateralMovement": {
            "id": "id_987",
            "success": true
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
| Cymulate.LateralMovement.success | Boolean | Lateral Movement assessment creation success status. | 

#### Command Example
```!cymulate-lateral-movement-stop```

#### Context Example
```json
{
    "Cymulate": {
        "LateralMovement": {
            "data": "ok",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Stopping lateral movement assessment:
>|data|success|
>|---|---|
>| ok | true |


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
| Cymulate.LateralMovement.inProgress | Boolean | Indicates whether the assessment is in progress.  | 


#### Command Example
```!cymulate-lateral-movement-status assessment_id="id_876"```

#### Context Example
```json
{
    "Cymulate": {
        "LateralMovement": {
            "id": "id_876",
            "inProgress": false
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
| Cymulate.Agent.agentMethod | String | The agent's methods. | 
| Cymulate.Agent.agentName | String | Agent name. | 
| Cymulate.Agent.comment | String | Comments. | 


#### Command Example
```!cymulate-agent-list```

#### Context Example
```json
{
    "Cymulate": {
        "Agent": [
            {
                "agentAddress": "test@cymulate.com",
                "agentMethod": "smtp",
                "comment": ""
            },
            {
                "agentAddress": "Cymulate_agent ",
                "agentMethod": "http",
                "agentName": "Cymulate_agent",
                "comment": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Agents list:
>|agentAddress|agentMethod|agentName|
>|---|---|---|
>| test@cymulate.com | smtp |  |
>| Cymulate_agent  | http | Cymulate_agent |


### cymulate-simulations-list
***
Retrieve a list of all simulations by ID.


#### Base Command

`cymulate-simulations-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| module | Module to retrieve events to. Possible values are: web-gateway, exfiltration, email-gateway, endpoint-security, waf, kill-chain, immediate-threats, phishing-awareness, lateral-movement. | Required | 
| attack_id | Attack ID. Can be retrieved using cymulate-simulations-id-list command. | Required | 


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
>| http://Google.com/ | SQL Injection | DB Agnostic | http://Google.com/ | N/A | id_001 | tel | post | Create a WAF Security rule to block incoming requests that contains.Validate that the specific input/url is protected with the MSSQL Injection signature pack (SQL Injection) | Web Application Firewall | ; exec master..xp_cmdshell 'ping 1.2.3.4'-- | OS Agnostic | blocked | high | http://Google.com | blocked | MSSQL Injection | 2021-02-28 16:33:41 | http://Google.com/ | 2021-02-28T14:33:41.485Z |
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
| from_date | From which date to fetch data. Format: YYYY-MM-DD, for example: March 1st 2021 should be written: 2021-03-01. . | Required | 
| to_date | End date to fetch data. Format: YYYY-MM-DD, for example: March 1st 2021 should be written: 2021-03-01. If no argument is given, default is now. | Optional | 


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
        "Simulations": [
            {
                "Agent": "Cymulate_agent_2",
                "ID": "id_b1",
                "Template": "Cobalt Group",
                "Timestamp": "2021-03-01 10:15:58.230000"
            },
            {
                "Agent": "Cymulate_agent_2",
                "ID": "id_b2",
                "Template": "Cobalt Group",
                "Timestamp": "2021-02-25 16:56:33.871000"
            },
            {
                "Agent": "info@cymulate.com",
                "ID": "id_b3",
                "Template": "Cobalt Group",
                "Timestamp": "2021-02-23 11:00:50.988000"
            }
        ]
    }
}
```

#### Human Readable Output

>### Displaying 3/3 Attack IDs:
>|Agent|ID|Template|Timestamp|
>|---|---|---|---|
>| Cymulate_agent_2 | id_b1 | Cobalt Group | 2021-03-01 10:15:58.230000 |
>| Cymulate_agent_2 | id_b2 | Cobalt Group | 2021-02-25 16:56:33.871000 |
>| info@cymulate.com | id_b3 | Cobalt Group | 2021-02-23 11:00:50.988000 |