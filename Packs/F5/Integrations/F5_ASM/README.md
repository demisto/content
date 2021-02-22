Use the F5 ASM integration to read information and to manage F5 firewall.
This integration was integrated and tested with version 15.1.0 of F5 ASM
## Configure F5 ASM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for F5 ASM.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., 8.8.8.8\) | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### f5-asm-policy-list
***
Lists all F5 Application Security Manager (ASM) policies.


#### Base Command

`f5-asm-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| self_link | A link to this resource. | Optional | 
| kind | A unique type identifier. | Optional | 
| items | items | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Policy.name | String | Display name of the policy. | 
| f5.Policy.active | Boolean | Indicates if the policy is active. | 
| f5.Policy.creatorName | String | The name of the user who created the policy. | 
| f5.Policy.createdTime | String | The time that the policy was created. | 
| f5.Policy.enforcementMode | Boolean | Indicates if the policy is in enforcement mode. | 
| f5.Policy.type | String | The policy type. | 


#### Command Example
```!f5-asm-policy-list```

#### Context Example
```
{
    "f5": {
        "ListPolicies": [
            {
                "active": null,
                "createdTime": null,
                "creatorName": "admin",
                "enforcementMode": null,
                "id": "d2wbyiegGUJDigyNPELJuQ",
                "name": "policy_to_delete",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/d2wbyiegGUJDigyNPELJuQ?ver=15.1.0",
                "type": "parent"
            },
            {
                "active": false,
                "createdTime": null,
                "creatorName": "admin",
                "enforcementMode": "transparent",
                "id": "WS7SYdAM7F3yexKVGPrm8w",
                "name": "technologies",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/WS7SYdAM7F3yexKVGPrm8w?ver=15.1.0",
                "type": "security"
            },
            {
                "active": false,
                "createdTime": null,
                "creatorName": "admin",
                "enforcementMode": "blocking",
                "id": "7FWxqE2a-3bbpJimP4amtA",
                "name": "server-tech",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA?ver=15.1.0",
                "type": "security"
            },
            {
                "active": true,
                "createdTime": null,
                "creatorName": "admin",
                "enforcementMode": "blocking",
                "id": "kpD2qFaUlGAbw8RhN5IFQA",
                "name": "Test_Policy",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0",
                "type": "security"
            },
            {
                "active": false,
                "createdTime": null,
                "creatorName": "admin",
                "enforcementMode": "blocking",
                "id": "eTzNEnVBWVG87KIljElZIw",
                "name": "Lior-test",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw?ver=15.1.0",
                "type": "security"
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for listing policies:
>|name|id|type|enforcementMode|selfLink|creatorName|active|
>|---|---|---|---|---|---|---|
>| policy_to_delete | d2wbyiegGUJDigyNPELJuQ | parent |  | https://localhost/mgmt/tm/asm/policies/d2wbyiegGUJDigyNPELJuQ?ver=15.1.0 | admin |  |
>| technologies | WS7SYdAM7F3yexKVGPrm8w | security | transparent | https://localhost/mgmt/tm/asm/policies/WS7SYdAM7F3yexKVGPrm8w?ver=15.1.0 | admin | false |
>| server-tech | 7FWxqE2a-3bbpJimP4amtA | security | blocking | https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA?ver=15.1.0 | admin | false |
>| Test_Policy | kpD2qFaUlGAbw8RhN5IFQA | security | blocking | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0 | admin | true |
>| Lior-test | eTzNEnVBWVG87KIljElZIw | security | blocking | https://localhost/mgmt/tm/asm/policies/eTzNEnVBWVG87KIljElZIw?ver=15.1.0 | admin | false |


### f5-asm-policy-create
***
Creates a new ASM policy.


#### Base Command

`f5-asm-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Display name of the policy. | Required | 
| description | Optional description for the policy. | Optional | 
| kind | The type of the policy. Possible values are: "parent" and "child". Default is "parent". | Required | 
| parent | The parent path if the policy is a security policy. | Optional | 
| enforcement_mode | The enforcement mode of the policy. Possible values are: "transparent" and "blocking". Default is "transparent". | Optional | 
| protocol_independent | Whether the policy is protocol independent. Default is "true". | Optional | 
| allow | Whether to allow the new policy. | Optional | 
| active | Whether to activate the new policy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Policy.name | String | Display name of the policy. | 
| f5.Policy.id | String | ID of the policy. | 
| f5.Policy.fullPath | String | Full path of the policy. | 
| f5.Policy.description | String | Description of the policy. | 
| f5.Policy.type | String | Type of the policy. | 
| f5.Policy.versionDatetime | String | The creation time of the policy. | 
| f5.Policy.selfLink | String | Policy self link | 


#### Command Example
```!f5-asm-policy-create name=Test_Policy_1 kind=parent```

#### Context Example
```
{
    "f5": {
        "CreatePolicy": {
            "description": "",
            "fullPath": "/Common/Test_Policy_1",
            "id": "qB5caokejf-8DZiNe_1VKw",
            "name": "Test_Policy_1",
            "serverTechnologyName": null,
            "type": "parent",
            "versionDatetime": "2020-10-06T11:00:44Z"
        }
    }
}
```

#### Human Readable Output

>### f5 data for creating policy:
>|name|id|fullPath|type|versionDatetime|
>|---|---|---|---|---|
>| Test_Policy_1 | qB5caokejf-8DZiNe_1VKw | /Common/Test_Policy_1 | parent | 2020-10-06T11:00:44Z |


### f5-asm-policy-apply
***
Applies a policy in the application security manager.


#### Base Command

`f5-asm-policy-apply`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_reference_link | Link to the policy to apply. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Policy.id | String | The policy ID. | 
| f5.Policy.kind | String | The type of the policy. | 
| f5.Policy.policyReference | String | The policy reference link. | 
| f5.Policy.status | String | The status of the policy. | 
| f5.Policy.startTime | String | The start time of the policy. | 


#### Command Example
```!f5-asm-policy-apply policy_reference_link="https://192.168.30.76/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0"```

#### Context Example
```
{
    "f5": {
        "ApplyPolicy": {
            "id": "eUa5aK7Ym-V3jgYV6C4wuw",
            "kind": "tm:asm:tasks:apply-policy:apply-policy-taskstate",
            "policyReference": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0",
            "startTime": "2020-10-06T11:00:46Z",
            "status": "NEW"
        }
    }
}
```

#### Human Readable Output

>### f5 data for applying policy:
>|policyReference|status|id|startTime|kind|
>|---|---|---|---|---|
>| https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0 | NEW | eUa5aK7Ym-V3jgYV6C4wuw | 2020-10-06T11:00:46Z | tm:asm:tasks:apply-policy:apply-policy-taskstate |


### f5-asm-policy-export-file
***
Exports a policy file.


#### Base Command

`f5-asm-policy-export-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filename | The name of the file to export the policy to. | Required | 
| policy_reference_link | The link to the policy to export. | Required | 
| minimal | Indicates whether to export only custom settings. Default is "true". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Policy.kind | String | The type of the policy. | 
| f5.Policy.format | String | The format of the policy. | 
| f5.Policy.filename | String | The filename of the exported file. | 
| f5.Policy.policyReference | String | The reference link to the policy. | 
| f5.Policy.id | String | The ID of the policy. | 
| f5.Policy.startTime | String | The start time of the policy. | 
| f5.Policy.status | String | The status of the policy. | 


#### Command Example
```!f5-asm-policy-export-file filename="exported_file.xml" policy_reference_link="https://192.168.30.76/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0"```

#### Context Example
```
{
    "f5": {
        "ExportPolicy": {
            "filename": "exported_file.xml",
            "format": "xml",
            "id": "WGIZaXwino-Kj0SBRfagHw",
            "kind": "tm:asm:tasks:export-policy:export-policy-taskstate",
            "policyReference": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0",
            "startTime": "2020-10-06T11:00:48Z",
            "status": "NEW"
        }
    }
}
```

#### Human Readable Output

>### f5 data for exporting policy:
>|policyReference|status|id|startTime|kind|format|filename|
>|---|---|---|---|---|---|---|
>| https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0 | NEW | WGIZaXwino-Kj0SBRfagHw | 2020-10-06T11:00:48Z | tm:asm:tasks:export-policy:export-policy-taskstate | xml | exported_file.xml |


### f5-asm-policy-methods-list
***
Lists the HTTP methods that are enforced in the security policy.


#### Base Command

`f5-asm-policy-methods-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 hash using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.PolicyMethods.name | String | The name of the method. | 
| f5.PolicyMethods.actAsMethod | String | The functionality of the method. | 
| f5.PolicyMethods.id | String | The ID of the method. | 
| f5.PolicyMethods.selfLink | String | The self link to the method. | 
| f5.PolicyMethods.kind | String | The type of endpoint. | 
| f5.PolicyMethods.lastUpdateMicros | String | The datetime the policy method was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-methods-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "PolicyMethods": [
            {
                "actAsMethod": "POST",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "mxy58ouQBKYZ7AsujHtdNQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-10-05T15:59:44Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "new_method_04",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/mxy58ouQBKYZ7AsujHtdNQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "POST",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "gbcCSqQgfttFwDszpHR8vg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-30T12:20:51Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "new_method_03",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/gbcCSqQgfttFwDszpHR8vg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "POST",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "p773WZAfmkgA-fTq6aqYzQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-30T12:20:28Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "new_method_02",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/p773WZAfmkgA-fTq6aqYzQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "POST",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "g1NIB_pTaAlM6YcpKrTFLg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-30T12:19:08Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "new_name_0101",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/g1NIB_pTaAlM6YcpKrTFLg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "POST",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "qBX6xVxyjS3v4faysUuE6A",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-30T12:02:58Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "new_method_01",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/qBX6xVxyjS3v4faysUuE6A?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "POST",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "QB1BzVdfL5WfSHrpP_2MOQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-11T12:32:56Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "test_get_2",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/QB1BzVdfL5WfSHrpP_2MOQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "GET",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "fY-VmdD8p450Aqd86HMKtQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-11T12:30:44Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "test_get",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/fY-VmdD8p450Aqd86HMKtQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "GET",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "9l8WogEiTHYEa8UzGruaBg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:07:26Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "getty",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/9l8WogEiTHYEa8UzGruaBg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "GET",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "4V4hb8HGOfeHsSMezfob-A",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T20:58:48Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "HEAD",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/4V4hb8HGOfeHsSMezfob-A?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "POST",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "oCQ57CKdi-DnSwwWAjkjEA",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T20:58:48Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "POST",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/oCQ57CKdi-DnSwwWAjkjEA?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": "GET",
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "dSgDWpPuac7bHb3bLwv8yA",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T20:58:48Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "GET",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/dSgDWpPuac7bHb3bLwv8yA?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for listing policy methods:
>|name|id|actAsMethod|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| new_method_04 | mxy58ouQBKYZ7AsujHtdNQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/mxy58ouQBKYZ7AsujHtdNQ?ver=15.1.0 | 2020-10-05T15:59:44Z |
>| new_method_03 | gbcCSqQgfttFwDszpHR8vg | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/gbcCSqQgfttFwDszpHR8vg?ver=15.1.0 | 2020-09-30T12:20:51Z |
>| new_method_02 | p773WZAfmkgA-fTq6aqYzQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/p773WZAfmkgA-fTq6aqYzQ?ver=15.1.0 | 2020-09-30T12:20:28Z |
>| new_name_0101 | g1NIB_pTaAlM6YcpKrTFLg | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/g1NIB_pTaAlM6YcpKrTFLg?ver=15.1.0 | 2020-09-30T12:19:08Z |
>| new_method_01 | qBX6xVxyjS3v4faysUuE6A | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/qBX6xVxyjS3v4faysUuE6A?ver=15.1.0 | 2020-09-30T12:02:58Z |
>| test_get_2 | QB1BzVdfL5WfSHrpP_2MOQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/QB1BzVdfL5WfSHrpP_2MOQ?ver=15.1.0 | 2020-08-11T12:32:56Z |
>| test_get | fY-VmdD8p450Aqd86HMKtQ | GET | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/fY-VmdD8p450Aqd86HMKtQ?ver=15.1.0 | 2020-08-11T12:30:44Z |
>| getty | 9l8WogEiTHYEa8UzGruaBg | GET | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/9l8WogEiTHYEa8UzGruaBg?ver=15.1.0 | 2020-08-05T21:07:26Z |
>| HEAD | 4V4hb8HGOfeHsSMezfob-A | GET | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/4V4hb8HGOfeHsSMezfob-A?ver=15.1.0 | 2020-08-05T20:58:48Z |
>| POST | oCQ57CKdi-DnSwwWAjkjEA | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/oCQ57CKdi-DnSwwWAjkjEA?ver=15.1.0 | 2020-08-05T20:58:48Z |
>| GET | dSgDWpPuac7bHb3bLwv8yA | GET | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/dSgDWpPuac7bHb3bLwv8yA?ver=15.1.0 | 2020-08-05T20:58:48Z |


### f5-asm-policy-file-types-list
***
Lists the file types that are allowed or not allowed in the security policy.


#### Base Command

`f5-asm-policy-file-types-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 hash using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.FileType.name | String | The name of the file type. | 
| f5.FileType.id | String | The ID of the file type. | 
| f5.FileType.selfLink | String | The self link to the file type. | 
| f5.FileType.kind | String | The type of endpoint. | 
| f5.FileType.lastUpdateMicros | String | The datetime the file type was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 
| f5.FileType.queryStringLength | String | The length of the query string. | 
| f5.FileType.checkRequestLength | String | The length of the request. | 
| f5.FileType.allowed | Boolean | Indicates if the file type is allowed. | 


#### Command Example
```!f5-asm-policy-file-types-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "FileType": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "Q3F1ukGRIQ7gBOHZN0lNCQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-14T12:31:25Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "pdf",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/Q3F1ukGRIQ7gBOHZN0lNCQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "Yoy1Z1_1JPPnGbeqLoj-Pw",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-03T14:25:22Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "csv",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/Yoy1Z1_1JPPnGbeqLoj-Pw?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "F2o7I8XjkrtcBH1IGTi9ew",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-03T14:22:09Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "yml",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/F2o7I8XjkrtcBH1IGTi9ew?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "D2NdDg84dP_4tYHBMubHpw",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-18T17:04:01Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "xml",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/D2NdDg84dP_4tYHBMubHpw?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "3-1bwXe4erMXxYTgZWatxg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:05:35Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "py",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/3-1bwXe4erMXxYTgZWatxg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "mOgzedRVODecKsTkfDvoHQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:05:11Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "exe",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/mOgzedRVODecKsTkfDvoHQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "M4na42GvebBMnI5wV_YMxg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-23T10:24:11Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "*",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/M4na42GvebBMnI5wV_YMxg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "wildcard",
                "valueType": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for listing policy file types:
>|name|id|type|selfLink|checkRequestLength|performStaging|allowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|
>| pdf | Q3F1ukGRIQ7gBOHZN0lNCQ | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/Q3F1ukGRIQ7gBOHZN0lNCQ?ver=15.1.0 | true | false | true | 2020-09-14T12:31:25Z |
>| csv | Yoy1Z1_1JPPnGbeqLoj-Pw | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/Yoy1Z1_1JPPnGbeqLoj-Pw?ver=15.1.0 | true | false | true | 2020-09-03T14:25:22Z |
>| yml | F2o7I8XjkrtcBH1IGTi9ew | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/F2o7I8XjkrtcBH1IGTi9ew?ver=15.1.0 | true | false | true | 2020-09-03T14:22:09Z |
>| xml | D2NdDg84dP_4tYHBMubHpw | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/D2NdDg84dP_4tYHBMubHpw?ver=15.1.0 | true | false | true | 2020-08-18T17:04:01Z |
>| py | 3-1bwXe4erMXxYTgZWatxg | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/3-1bwXe4erMXxYTgZWatxg?ver=15.1.0 | true | false | true | 2020-08-05T21:05:35Z |
>| exe | mOgzedRVODecKsTkfDvoHQ | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/mOgzedRVODecKsTkfDvoHQ?ver=15.1.0 | true | false | true | 2020-08-05T21:05:11Z |
>| * | M4na42GvebBMnI5wV_YMxg | wildcard | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/M4na42GvebBMnI5wV_YMxg?ver=15.1.0 | true | false | true | 2020-08-23T10:24:11Z |


### f5-asm-policy-methods-add
***
Adds a new allowed method.


#### Base Command

`f5-asm-policy-methods-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy to which to add the method. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| new_method_name | The display name of the new method. | Required | 
| act_as_method | Functionality of the new method. Possible values are: "GET" and "POST". Default is "GET". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.PolicyMethods.name | String | The name of the new method. | 
| f5.PolicyMethods.id | String | The ID of the new method. | 
| f5.PolicyMethods.actAsMethod | String | The functionality of the new method. | 
| f5.PolicyMethods.selfLink | String | The self link to the method. | 
| f5.PolicyMethods.kind | String | The type of method. | 


#### Command Example
```!f5-asm-policy-methods-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA new_method_name="Posty" act_as_method="POST"```

#### Context Example
```
{
    "f5": {
        "PolicyMethods": {
            "actAsMethod": "POST",
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "cwMuAdnzCUXmGBTc552zvQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:00:58Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "Posty",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding policy methods:
>|name|id|actAsMethod|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| Posty | cwMuAdnzCUXmGBTc552zvQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0 | 2020-10-06T11:00:58Z |


### f5-asm-policy-methods-update
***
Updates a policy method.


#### Base Command

`f5-asm-policy-methods-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy in which to update the method. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| method_id | The ID of the method to update. The method_ID or method_name arguments must be filled. Default is "None". | Optional | 
| method_name | Display name of the method to update. The method_ID or method_name argument must be filled. Default is "None". | Optional | 
| act_as_method | Functionality of the updated method. Possible values are: "GET" and "POST". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.PolicyMethods.name | String | The name of the updated method. | 
| f5.PolicyMethods.id | String | The ID of the updated method. | 
| f5.PolicyMethods.actAsMethod | String | The functionality of the updated method. | 
| f5.PolicyMethods.selfLink | String | The self link to the updated method. | 
| f5.PolicyMethods.kind | String | The type of method. | 


#### Command Example
```!f5-asm-policy-methods-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA method_name="Posty" act_as_method="POST"```

#### Context Example
```
{
    "f5": {
        "PolicyMethods": {
            "actAsMethod": "POST",
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "cwMuAdnzCUXmGBTc552zvQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:00:58Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "Posty",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for updating policy methods:
>|name|id|actAsMethod|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| Posty | cwMuAdnzCUXmGBTc552zvQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0 | 2020-10-06T11:00:58Z |


### f5-asm-policy-methods-delete
***
Deletes a method from a given policy.


#### Base Command

`f5-asm-policy-methods-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy from which to delete the method. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| method_id | The ID of the method to delete. The method_ID or method_name argument must be filled. Default is "None". | Optional | 
| method_name | The display name of the method to delete. The method_ID or method_name argument must be filled. Default is "None". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.PolicyMethods.name | String | The name of the deleted method. | 
| f5.PolicyMethods.id | String | The ID of the deleted method. | 
| f5.PolicyMethods.actAsMethod | String | The functionality of the deleted method. | 
| f5.PolicyMethods.selfLink | String | The self link to the deleted method. | 
| f5.PolicyMethods.kind | String | The type of the deleted method. | 


#### Command Example
```!f5-asm-policy-methods-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA method_name="Posty"```

#### Context Example
```
{
    "f5": {
        "PolicyMethods": {
            "actAsMethod": "POST",
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "cwMuAdnzCUXmGBTc552zvQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:00:58Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "Posty",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting policy methods:
>|name|id|actAsMethod|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| Posty | cwMuAdnzCUXmGBTc552zvQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0 | 2020-10-06T11:00:58Z |


### f5-asm-policy-file-types-add
***
add new file type


#### Base Command

`f5-asm-policy-file-types-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy to which you want to add the new file type. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| new_file_type | The new file type to add. | Required | 
| query_string_length | The length of the query string. Default is "100". | Optional | 
| check_post_data_length | Whether to check the length of the data in the post method. Default is "true". | Optional | 
| response_check | Whether to check the response. Default is "true". | Optional | 
| check_request_length | Whether to check the length of the request. Default is "true". | Optional | 
| post_data_length | The post data length. Default is "100". | Optional | 
| perform_staging | Whether to stage the new file type. Default is "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.FileType.name | String | The name of the file type. | 
| f5.FileType.id | String | The ID of the file type. | 
| f5.FileType.queryStringLength | Number | The length of the query string. | 
| f5.FileType.selfLink | String | The self link to the file type. | 
| f5.FileType.lastUpdateMicros | String | The datetime the file type was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 
| f5.FileType.responseCheck | Boolean | Indicates if user wanted to check the response. | 
| f5.FileType.checkRequestLength | String | The length of the request. | 
| f5.FileType.allowed | Boolean | Indicates if the file type is allowed. | 
| f5.FileType.check-url-length | Boolean | Indicates whether to check the URL length. | 
| f5.FileType.postDataLength | Number | The length of the post data. | 
| f5.FileType.urlLength | Number | The length of the URL. | 
| f5.FileType.performStaging | Boolean | Indicates whether the file type should be staged. | 


#### Command Example
```!f5-asm-policy-file-types-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA new_file_type="txt"```

#### Context Example
```
{
    "f5": {
        "FileType": {
            "actAsMethod": null,
            "allowed": true,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": true,
            "checkUrlLength": false,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "x4JPPU1fey8i0DR1jB6UVA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:08Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "txt",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": 100,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": true,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding policy file types:
>|name|id|type|selfLink|checkRequestLength|responseCheck|checkUrlLength|postDataLength|performStaging|allowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|
>| txt | x4JPPU1fey8i0DR1jB6UVA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0 | true | true | false | 100 | false | true | 2020-10-06T11:01:08Z |


### f5-asm-policy-file-types-update
***
Updates the policy file type.


#### Base Command

`f5-asm-policy-file-types-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| file_type_id | ID of the file type. The ID or display name must be filled. Default is "None". | Optional | 
| file_type_name | Display name of the file type. The ID or display name must be filled. Default is "None". | Optional | 
| query_string_length | The length of the query string. Default is "100". | Optional | 
| check_post_data_length | Whether to check the length of the data in the post method. Default is "True". | Optional | 
| response_check | Whether to check the response. Default is "true". | Optional | 
| check_request_length | Whether to check the length of the request. Default is "true". | Optional | 
| post_data_length | The post data length. Default is "100". | Optional | 
| perform_staging | Whether to stage the updated file type. Default is "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.FileType.name | String | The name of the file type. | 
| f5.FileType.id | String | The ID of the file type. | 
| f5.FileType.queryStringLength | Number | The length of the query string. | 
| f5.FileType.selfLink | String | The self link to the file type. | 
| f5.FileType.lastUpdateMicros | String | The datetime the file type was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 
| f5.FileType.responseCheck | Boolean | Indicates whether the user wanted to check the response. | 
| f5.FileType.checkRequestLength | String | The length of the request. | 
| f5.FileType.allowed | Boolean | Indicates if the file type is allowed. | 
| f5.FileType.check-url-length | Boolean | Indicates whether the user wanted to check the URL length. | 
| f5.FileType.postDataLength | Number | The length of the post data. | 
| f5.FileType.urlLength | Number | The length of the URL. | 
| f5.FileType.performStaging | Boolean | Indicates whether the file type should be staged. | 


#### Command Example
```!f5-asm-policy-file-types-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA file_type_name="txt"```

#### Context Example
```
{
    "f5": {
        "FileType": {
            "actAsMethod": null,
            "allowed": true,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": true,
            "checkUrlLength": false,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "x4JPPU1fey8i0DR1jB6UVA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:08Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "txt",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": 100,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": true,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for updating policy methods:
>|name|id|type|selfLink|checkRequestLength|responseCheck|checkUrlLength|postDataLength|performStaging|allowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|
>| txt | x4JPPU1fey8i0DR1jB6UVA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0 | true | true | false | 100 | false | true | 2020-10-06T11:01:08Z |


### f5-asm-policy-file-types-delete
***
Deletes the policy file type.


#### Base Command

`f5-asm-policy-file-types-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| file_type_id | ID of the file type. The ID or display name must be filled. Default is "None". | Optional | 
| file_type_name | Display name of the file type. The ID or display name must be filled. Default is "None". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.FileType.name | String | Display name of the policy. | 
| f5.FileType.id | String | ID of the policy that was deleted. | 
| f5.FileType.selfLink | String | The self link to the deleted policy. | 


#### Command Example
```!f5-asm-policy-file-types-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA file_type_name="txt"```

#### Context Example
```
{
    "f5": {
        "FileType": {
            "actAsMethod": null,
            "allowed": true,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": true,
            "checkUrlLength": false,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "x4JPPU1fey8i0DR1jB6UVA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:08Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "txt",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": 100,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": true,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting policy file type:
>|name|id|type|selfLink|checkRequestLength|responseCheck|checkUrlLength|postDataLength|performStaging|allowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|
>| txt | x4JPPU1fey8i0DR1jB6UVA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0 | true | true | false | 100 | false | true | 2020-10-06T11:01:08Z |


### f5-asm-policy-delete
***
Deletes a policy.


#### Base Command

`f5-asm-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Policy.name | String | Display name of the deleted policy. | 
| f5.Policy.id | String | ID of the deleted policy. | 
| f5.Policy.selfLink | String | The self link to the deleted policy. | 


#### Command Example
```!f5-asm-policy-delete policy_md5=d2wbyiegGUJDigyNPELJuQ```

#### Context Example
```
{
    "f5": {
        "DeletePolicy": {
            "id": "d2wbyiegGUJDigyNPELJuQ",
            "name": "policy_to_delete",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/d2wbyiegGUJDigyNPELJuQ?ver=15.1.0",
            "serverTechnologyName": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting policy:
>|name|id|selfLink|
>|---|---|---|
>| policy_to_delete | d2wbyiegGUJDigyNPELJuQ | https://localhost/mgmt/tm/asm/policies/d2wbyiegGUJDigyNPELJuQ?ver=15.1.0 |


### f5-asm-policy-hostnames-list
***
Lists the hostnames of the policy.


#### Base Command

`f5-asm-policy-hostnames-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Hostname.name | String | The hostname of the policy. | 
| f5.Hostname.id | String | The ID of the hostname. | 
| f5.Hostname.createdBy | String | The interface used to create the hostname. | 
| f5.Hostname.selfLink | String | The self link to the specific hostname. | 
| f5.Hostname.includeSubdomains | Boolean | Indicates whether to include subdomains. | 
| f5.Hostname.lastUpdateMicros | String | The datetime the hostname was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-hostnames-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "Hostname": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "Wrq9YDsieAMC3Y2DSY5Rcg",
                "ignoreAnomalies": null,
                "includeSubdomains": true,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-01T12:22:17Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "example.com",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/Wrq9YDsieAMC3Y2DSY5Rcg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "tM6UhfuSaPYYRnUS6-k2vg",
                "ignoreAnomalies": null,
                "includeSubdomains": false,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-01T12:36:37Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "qmasters.co.il",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/tM6UhfuSaPYYRnUS6-k2vg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "_3pBVxU6gHchLIdX_Tm4vQ",
                "ignoreAnomalies": null,
                "includeSubdomains": false,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:09:06Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "cnn",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/_3pBVxU6gHchLIdX_Tm4vQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "HVkg9LRLJ6gCvXfE8FNvWg",
                "ignoreAnomalies": null,
                "includeSubdomains": false,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:08:39Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "google.com",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/HVkg9LRLJ6gCvXfE8FNvWg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for listing policy hostname:
>|name|id|selfLink|includeSubdomains|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|
>| example.com | Wrq9YDsieAMC3Y2DSY5Rcg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/Wrq9YDsieAMC3Y2DSY5Rcg?ver=15.1.0 | true | GUI | 2020-09-01T12:22:17Z |
>| qmasters.co.il | tM6UhfuSaPYYRnUS6-k2vg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/tM6UhfuSaPYYRnUS6-k2vg?ver=15.1.0 | false | GUI | 2020-09-01T12:36:37Z |
>| cnn | _3pBVxU6gHchLIdX_Tm4vQ | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/_3pBVxU6gHchLIdX_Tm4vQ?ver=15.1.0 | false | GUI | 2020-08-05T21:09:06Z |
>| google.com | HVkg9LRLJ6gCvXfE8FNvWg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/HVkg9LRLJ6gCvXfE8FNvWg?ver=15.1.0 | false | GUI | 2020-08-05T21:08:39Z |


### f5-asm-policy-hostnames-add
***
Adds a new hostname to a policy.


#### Base Command

`f5-asm-policy-hostnames-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| name | The hostname to add to the policy. | Required | 
| include_subdomains | Whether to include subdomains in the policy. Default is "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Hostname.name | String | The policy hostname. | 
| f5.Hostname.id | String | The policy ID. | 
| f5.Hostname.createdBy | String | The interface used to create the hostname. | 
| f5.Hostname.selfLink | String | The self link to the specific hostname. | 
| f5.Hostname.includeSubdomains | Boolean | Indicates whether to include subdomains. | 
| f5.Hostname.lastUpdateMicros | String | The datetime the hostname was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-hostnames-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA name=qmasters.co```

#### Context Example
```
{
    "f5": {
        "Hostname": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "dsblcoDkMkFb_A_H6BS6eA",
            "ignoreAnomalies": null,
            "includeSubdomains": false,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:25Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "qmasters.co",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding policy hostname:
>|name|id|selfLink|includeSubdomains|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|
>| qmasters.co | dsblcoDkMkFb_A_H6BS6eA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0 | false | GUI | 2020-10-06T11:01:25Z |


### f5-asm-policy-hostnames-update
***
Updates an existing policy hostname.


#### Base Command

`f5-asm-policy-hostnames-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| hostname_id | ID of the hostname. ID or display name must be filled. Default is "None". | Optional | 
| hostname_name | Display name of the hostname. ID or display name must be filled. Default is "None". | Optional | 
| include_subdomains | Whether to include subdomains. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Hostname.name | String | The policy hostname. | 
| f5.Hostname.id | String | The policy ID. | 
| f5.Hostname.createdBy | String | The interface used to create the hostname. | 
| f5.Hostname.selfLink | String | The self link to the specific hostname. | 
| f5.Hostname.includeSubdomains | Boolean | Indicates whether subdomains are included. | 
| f5.Hostname.lastUpdateMicros | String | The datetime the hostname was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-hostnames-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA hostname_name=qmasters.co include_subdomains=true```

#### Context Example
```
{
    "f5": {
        "Hostname": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "dsblcoDkMkFb_A_H6BS6eA",
            "ignoreAnomalies": null,
            "includeSubdomains": true,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:27Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "qmasters.co",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for updating hostname:
>|name|id|selfLink|includeSubdomains|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|
>| qmasters.co | dsblcoDkMkFb_A_H6BS6eA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0 | true | GUI | 2020-10-06T11:01:27Z |


### f5-asm-policy-hostnames-delete
***
Deletes a hostname from a policy.


#### Base Command

`f5-asm-policy-hostnames-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| hostname_id | The ID of the hostname. The ID or display name must be filled. Default is "None". | Optional | 
| hostname_name | The display name of the hostname. The ID or display name must be filled. Default is "None". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Hostname.name | String | The policy hostname. | 
| f5.Hostname.id | String | The policy ID. | 
| f5.Hostname.createdBy | String | The interface used to create the hostname. | 
| f5.Hostname.selfLink | String | The self link to the specific hostname. | 
| f5.Hostname.includeSubdomains | Boolean | Whether to include subdomains. | 
| f5.Hostname.lastUpdateMicros | String | The datetime the hostname was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-hostnames-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA hostname_name=qmasters.co```

#### Context Example
```
{
    "f5": {
        "Hostname": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "dsblcoDkMkFb_A_H6BS6eA",
            "ignoreAnomalies": null,
            "includeSubdomains": true,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:27Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "qmasters.co",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting hostname:
>|name|id|selfLink|includeSubdomains|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|
>| qmasters.co | dsblcoDkMkFb_A_H6BS6eA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0 | true | GUI | 2020-10-06T11:01:27Z |


### f5-asm-policy-cookies-list
***
Lists all cookies of a given policy.


#### Base Command

`f5-asm-policy-cookies-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Cookies.name | String | The name of the cookie. | 
| f5.Cookies.id | String | The ID of the cookie. | 
| f5.Cookies.selfLink | String | The self link to the specific cookie. | 
| f5.Cookies.enforcementType | String | The enforcement type of the cookie. | 
| f5.Cookies.performStaging | Boolean | Indicates whether the cookie should be staged. | 
| f5.Cookies.kind | String | The cookie type. | 
| f5.Cookies.isBase64 | Boolean | Indicates if the cookie is encoded in base64. | 
| f5.Cookies.createdBy | String | Indicates which user created this cookie. | 


#### Command Example
```!f5-asm-policy-cookies-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "Cookies": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": "allow",
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "6qrK8k_J8uIbW-r9fgQiCw",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-22T11:37:17Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "not_mal",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/6qrK8k_J8uIbW-r9fgQiCw?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": "allow",
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "w3iYXWKemaToYhPbDNXnDQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-10-01T16:48:41Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "chocolate",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/w3iYXWKemaToYhPbDNXnDQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "wildcard",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": "allow",
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "E1g7FVU2CYuY30F-Rp_MUw",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:04:51Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "yummy",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/E1g7FVU2CYuY30F-Rp_MUw?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": "allow",
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "HeC08NE594GztN6H7bTecA",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:04:43Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "yum",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/HeC08NE594GztN6H7bTecA?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": "allow",
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "M4na42GvebBMnI5wV_YMxg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-23T10:24:10Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "*",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/M4na42GvebBMnI5wV_YMxg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "wildcard",
                "valueType": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for listing policy cookies:
>|name|id|type|selfLink|enforcementType|attackSignaturesCheck|isBase64|performStaging|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| not_mal | 6qrK8k_J8uIbW-r9fgQiCw | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/6qrK8k_J8uIbW-r9fgQiCw?ver=15.1.0 | allow | true | false | false | GUI | 2020-09-22T11:37:17Z |
>| chocolate | w3iYXWKemaToYhPbDNXnDQ | wildcard | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/w3iYXWKemaToYhPbDNXnDQ?ver=15.1.0 | allow | true | false | false | GUI | 2020-10-01T16:48:41Z |
>| yummy | E1g7FVU2CYuY30F-Rp_MUw | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/E1g7FVU2CYuY30F-Rp_MUw?ver=15.1.0 | allow | true | false | false | GUI | 2020-08-05T21:04:51Z |
>| yum | HeC08NE594GztN6H7bTecA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/HeC08NE594GztN6H7bTecA?ver=15.1.0 | allow | true | false | false | GUI | 2020-08-05T21:04:43Z |
>| * | M4na42GvebBMnI5wV_YMxg | wildcard | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/M4na42GvebBMnI5wV_YMxg?ver=15.1.0 | allow | true | false | false | GUI | 2020-08-23T10:24:10Z |


### f5-asm-policy-blocking-settings-list
***
Retrieves a blocking-settings list from a selected policy.


#### Base Command

`f5-asm-policy-blocking-settings-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| endpoint | Sub-path of the blocking- settings element. Possible values are: "violations", "evasions", "http-protocols", and "web-services-securities". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.BlockingSettings.description | String | Description of the element. | 
| f5.BlockingSettings.learn | Boolean | Indicates whether the element is learning. | 
| f5.BlockingSettings.id | String | The element ID. | 
| f5.BlockingSettings.kind | String | The type of element. | 
| f5.BlockingSettings.enabled | Boolean | Whether the element is enabled. | 
| f5.BlockingSettings.selfLink | String | The self link to the specific element. | 
| f5.BlockingSettings.reference | String | Reference to the element. | 
| f5.BlockingSettings.lastUpdateMicros | String | The datetime the element was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 
| f5.BlockingSettings.section-reference | String | Section reference to the element. | 
| f5.BlockingSettings.alarm | Boolean | Whether the system records requests that trigger the violation. | 
| f5.BlockingSettings.block | Boolean | Whether the element blocks the request that triggers the violation. | 


#### Command Example
```!f5-asm-policy-blocking-settings-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA endpoint=evasions```

#### Context Example
```
{
    "f5": {
        "evasions": [
            {
                "alarm": null,
                "block": null,
                "description": "Bad unescape",
                "enabled": false,
                "id": "9--k-GSum4jUNSf0sU91Dw",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "lastUpdateMicros": "2020-08-16T10:18:55Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0",
                "section-reference": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "Apache whitespace",
                "enabled": false,
                "id": "Ahu8fuILcRNNU-ICBr1v6w",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "lastUpdateMicros": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0",
                "section-reference": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "Bare byte decoding",
                "enabled": false,
                "id": "EKfN2XD-E1z097tVwOO1nw",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "lastUpdateMicros": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0",
                "section-reference": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "IIS Unicode codepoints",
                "enabled": false,
                "id": "dtxhHW66r8ZswIeccbXbXA",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "lastUpdateMicros": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0",
                "section-reference": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "IIS backslashes",
                "enabled": false,
                "id": "6l0vHEYIIy4H06o9mY5RNQ",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "lastUpdateMicros": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0",
                "section-reference": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "%u decoding",
                "enabled": false,
                "id": "Y2TT8PSVtqudz407XG4LAQ",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "lastUpdateMicros": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0",
                "section-reference": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "Multiple decoding",
                "enabled": false,
                "id": "x02XsB6uJX5Eqp1brel7rw",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "lastUpdateMicros": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0",
                "section-reference": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "Directory traversals",
                "enabled": false,
                "id": "qH_2eaLz5x2RgaZ7dUISLA",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "lastUpdateMicros": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0",
                "section-reference": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### Evasions for selected policy
>|id|description|enabled|learn|kind|reference|selfLink|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|
>| 9--k-GSum4jUNSf0sU91Dw | Bad unescape | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0 | 2020-08-16T10:18:55Z |
>| Ahu8fuILcRNNU-ICBr1v6w | Apache whitespace | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| EKfN2XD-E1z097tVwOO1nw | Bare byte decoding | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| dtxhHW66r8ZswIeccbXbXA | IIS Unicode codepoints | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| 6l0vHEYIIy4H06o9mY5RNQ | IIS backslashes | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| Y2TT8PSVtqudz407XG4LAQ | %u decoding | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| x02XsB6uJX5Eqp1brel7rw | Multiple decoding | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| qH_2eaLz5x2RgaZ7dUISLA | Directory traversals | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0 | 2020-08-05T20:58:49Z |


### f5-asm-policy-blocking-settings-update
***
Updates a blocking-settings element.


#### Base Command

`f5-asm-policy-blocking-settings-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| endpoint | Sub-path of the blocking- settings element. Possible values are: "violations", "evasions", "http-protocols", and "web-services-securities". | Required | 
| description | Description (or name) of the element. | Required | 
| learn | Whether the element should learn. | Optional | 
| alarm | Whether the system records requests that trigger the violation. | Optional | 
| block | Whether the element blocks the request that triggers the violation. | Optional | 
| enabled | Whether the element should be enabled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.BlockingSettings.description | String | The description of the element. | 
| f5.BlockingSettings.learn | Boolean | Whether the element is learning. | 
| f5.BlockingSettings.id | String | The ID of the element. | 
| f5.BlockingSettings.kind | String | The type of element. | 
| f5.BlockingSettings.enabled | Boolean | Whether the element is enabled. | 
| f5.BlockingSettings.selfLink | String | The self link to the specific element. | 
| f5.BlockingSettings.reference | String | The reference to the element. | 
| f5.BlockingSettings.lastUpdateMicros | String | The datetime the resource was last updated represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 
| f5.BlockingSettings.section-reference | String | The section reference to the element. | 
| f5.BlockingSettings.alarm | Boolean | Whether the system records requests that trigger the violation. | 
| f5.BlockingSettings.block | Boolean | Whether the element blocks the request that triggers the violation. | 


#### Command Example
```!f5-asm-policy-blocking-settings-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA endpoint=evasions description="Bad unescape"```

#### Context Example
```
{
    "f5": {
        "evasions": {
            "alarm": null,
            "block": null,
            "description": "Bad unescape",
            "enabled": false,
            "id": "9--k-GSum4jUNSf0sU91Dw",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "lastUpdateMicros": "2020-08-16T10:18:55Z",
            "learn": true,
            "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0",
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0"
        }
    }
}
```

#### Human Readable Output

>### Modified evasions
>|id|description|enabled|learn|kind|reference|selfLink|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|
>| 9--k-GSum4jUNSf0sU91Dw | Bad unescape | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0 | 2020-08-16T10:18:55Z |


### f5-asm-policy-urls-list
***
Lists all policy URLs.


#### Base Command

`f5-asm-policy-urls-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Url.id | String | The ID of the URL. | 
| f5.Url.name | String | The name of the URL. | 
| f5.Url.description | String | A description of the URL. | 
| f5.Url.protocol | String | The protocol the URL uses. | 
| f5.Url.type | String | Whether the URL is explicit or a wildcard. | 
| f5.Url.method | String | The allowed method \(or all methods\) of the URL. | 
| f5.Url.isAllowed | Boolean | Whether the URL is allowed. | 
| f5.Url.clickjackingProtection | Boolean | Whether clickjacking protection is enabled in the URL. | 
| f5.Url.performStaging | Boolean | Indicates whether the URL should be staged. | 
| f5.Url.mandatoryBody | Boolean | Whether a request body is mandatory. | 
| f5.Url.selfLink | String | The self link to the URL in the API. | 
| f5.Url.lastUpdateMicros | String | The datetime the last update was committed to the URL represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-urls-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "Url": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": false,
                "createdBy": "GUI",
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "h89DiM-YtWptqKb9c0egbA",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": true,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-18T15:04:39Z",
                "mandatory": null,
                "mandatoryBody": false,
                "metacharElementCheck": null,
                "method": "*",
                "name": "/http_example_2",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": "http",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/h89DiM-YtWptqKb9c0egbA?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": false,
                "createdBy": "GUI",
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "q_O5IGzUqSmFYZhlkA1CpQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": true,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-18T14:55:47Z",
                "mandatory": null,
                "mandatoryBody": false,
                "metacharElementCheck": null,
                "method": "*",
                "name": "/http_example",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": "http",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/q_O5IGzUqSmFYZhlkA1CpQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": false,
                "createdBy": "GUI",
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "2lQ1Z3wue9pdEjZxE-L_ZQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": true,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-11T17:06:05Z",
                "mandatory": null,
                "mandatoryBody": false,
                "metacharElementCheck": null,
                "method": "*",
                "name": "/http_examplel",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": "http",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/2lQ1Z3wue9pdEjZxE-L_ZQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "6ER7SOq208zow5rraOzwyQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": false,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-11T14:00:44Z",
                "mandatory": null,
                "mandatoryBody": true,
                "metacharElementCheck": null,
                "method": "*",
                "name": "/http",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": "http",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/6ER7SOq208zow5rraOzwyQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "explicit",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": false,
                "createdBy": "GUI",
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "faiefv884qtHRU3Qva2AbQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": true,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-20T15:24:11Z",
                "mandatory": null,
                "mandatoryBody": false,
                "metacharElementCheck": null,
                "method": "*",
                "name": "*",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": "http",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/faiefv884qtHRU3Qva2AbQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "wildcard",
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": false,
                "createdBy": "GUI",
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "N_a3D1S7OKDehYEPb-mgCg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": true,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-20T15:24:11Z",
                "mandatory": null,
                "mandatoryBody": false,
                "metacharElementCheck": null,
                "method": "*",
                "name": "*",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": "https",
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/N_a3D1S7OKDehYEPb-mgCg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "wildcard",
                "valueType": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for listing policy url:
>|name|id|type|protocol|method|selfLink|mandatoryBody|clickjackingProtection|attackSignaturesCheck|performStaging|isAllowed|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| /http_example_2 | h89DiM-YtWptqKb9c0egbA | explicit | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/h89DiM-YtWptqKb9c0egbA?ver=15.1.0 | false | false | true | false | true | GUI | 2020-08-18T15:04:39Z |
>| /http_example | q_O5IGzUqSmFYZhlkA1CpQ | explicit | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/q_O5IGzUqSmFYZhlkA1CpQ?ver=15.1.0 | false | false | true | false | true | GUI | 2020-08-18T14:55:47Z |
>| /http_examplel | 2lQ1Z3wue9pdEjZxE-L_ZQ | explicit | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/2lQ1Z3wue9pdEjZxE-L_ZQ?ver=15.1.0 | false | false | true | false | true | GUI | 2020-08-11T17:06:05Z |
>| /http | 6ER7SOq208zow5rraOzwyQ | explicit | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/6ER7SOq208zow5rraOzwyQ?ver=15.1.0 | true |  |  |  | false | GUI | 2020-08-11T14:00:44Z |
>| * | faiefv884qtHRU3Qva2AbQ | wildcard | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/faiefv884qtHRU3Qva2AbQ?ver=15.1.0 | false | false | true | false | true | GUI | 2020-08-20T15:24:11Z |
>| * | N_a3D1S7OKDehYEPb-mgCg | wildcard | https | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/N_a3D1S7OKDehYEPb-mgCg?ver=15.1.0 | false | false | true | false | true | GUI | 2020-08-20T15:24:11Z |


### f5-asm-policy-cookies-add
***
Adds a new cookie to a specific policy.


#### Base Command

`f5-asm-policy-cookies-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| new_cookie_name | The new cookie name to add. | Required | 
| perform_staging | Whether to stage the new cookie. Default is "false". | Optional | 
| parameter_type | Type of the new parameter. Possible values are: "explicit" and "wildcard". Default is "explicit". | Optional | 
| enforcement_type | The enforcement type. Possible values are: "allow" and "enforce". Default is "allow". | Optional | 
| attack_signatures_check | Whether attack signatures should be checked. Default is "true". If the enforcement type is set to "enforce", this field will not get any value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Cookies.name | String | The name of the cookie. | 
| f5.Cookies.id | String | The ID of the cookie. | 
| f5.Cookies.selfLink | String | The self link to the specific cookie. | 
| f5.Cookies.enforcementType | String | The enforcement type. | 
| f5.Cookies.performStaging | Boolean | Indicates whether the cookie should be staged. | 
| f5.Cookies.type | String | The type of the cookie. | 
| f5.Cookies.isBase64 | Boolean | Indicates if the cookie is encoded in base64. | 
| f5.Cookies.createdBy | String | Indicates who created the cookie. | 


#### Command Example
```!f5-asm-policy-cookies-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA new_cookie_name=new_cookie```

#### Context Example
```
{
    "f5": {
        "Cookies": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": "allow",
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "7t_U2dbYEAQp89Wp0m_QoA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": false,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:17Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "new_cookie",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding policy cookie: new_cookie
>|name|id|type|selfLink|enforcementType|isBase64|attackSignaturesCheck|createdBy|performStaging|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| new_cookie | 7t_U2dbYEAQp89Wp0m_QoA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0 | allow | false | true | GUI | false | 2020-10-06T11:01:17Z |


### f5-asm-policy-urls-add
***
Adds a new URL to a policy.


#### Base Command

`f5-asm-policy-urls-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| protocol | The communication protocol. Possible values are: "http" and "https". | Required | 
| name | Display name of the new URL. | Required | 
| description | An optional description for the URL. | Optional | 
| url_type | The type of URL. Possible values are: "explicit" and "wildcard". | Optional | 
| is_allowed | Whether the URL is allowed. Default is "true". | Optional | 
| method | The method to use in the URL. | Optional | 
| clickjacking_protection | Whether clickjacking protection is enabled in the URL. | Optional | 
| perform_staging | Whether to stage the URL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Url.id | String | The ID of the URL. | 
| f5.Url.name | String | The name of the URL. | 
| f5.Url.description | String | A description of the URL. | 
| f5.Url.protocol | String | The protocol the URL uses. | 
| f5.Url.type | String | Whether the URL is explicit or wildcard. | 
| f5.Url.method | String | The allowed method \(or all\) of the URL. | 
| f5.Url.isAllowed | Boolean | Whether the URL is allowed. | 
| f5.Url.clickjackingProtection | Boolean | Whether clickjacking protection is enabled in the URL. | 
| f5.Url.performStaging | Boolean | Indicates whether the URL should be staged. | 
| f5.Url.mandatoryBody | Boolean | Whether a request body is mandatory. | 
| f5.Url.selfLink | String | The self link to the specific URL in the API. | 
| f5.Url.lastUpdateMicros | String | The datetime the last update was committed to the URL represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-urls-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA protocol=https name=validation```

#### Context Example
```
{
    "f5": {
        "Url": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": false,
            "createdBy": "GUI",
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "Q6tL31BrUl-vlY0yKsNSqA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": true,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:46Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": "*",
            "name": "/validation",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": "https",
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding policy url:
>|name|id|type|protocol|method|selfLink|clickjackingProtection|attackSignaturesCheck|createdBy|performStaging|isAllowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| /validation | Q6tL31BrUl-vlY0yKsNSqA | explicit | https | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0 | false | true | GUI | false | true | 2020-10-06T11:01:46Z |


### f5-asm-policy-urls-update
***
Updates an existing policy URL.


#### Base Command

`f5-asm-policy-urls-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| url_id | The ID of the URL. The ID or display name must be filled. Default is "None". | Optional | 
| url_name | The display name of the URL. The ID or display name must be filled. Default is "None". | Optional | 
| perform_staging | Whether to stage the URL. | Optional | 
| description | Optional new description for the URL. | Optional | 
| mandatory_body | Whether a body is mandatory. | Optional | 
| url_isreferrer | Whether the URL is a referrer. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Url.id | String | the ID of the URL. | 
| f5.Url.name | String | The name of the URL. | 
| f5.Url.description | String | A description of the URL. | 
| f5.Url.protocol | String | The protocol the URL uses. | 
| f5.Url.type | String | Whether the URL is explicit or wildcard. | 
| f5.Url.method | String | The allowed method \(or all\) of the URL. | 
| f5.Url.isAllowed | Boolean | Whether the URL is allowed. | 
| f5.Url.clickjackingProtection | Boolean | Whether clickjacking protection is enabled in the URL. | 
| f5.Url.performStaging | Boolean | Indicates whether the URL should be staged. | 
| f5.Url.mandatoryBody | Boolean | Whether a request body is mandatory. | 
| f5.Url.selfLink | String | The self link to the specific URL in the API. | 
| f5.Url.lastUpdateMicros | String | The datetime the last update was committed to the URL represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-urls-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA  url_name=/validation```

#### Context Example
```
{
    "f5": {
        "Url": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": false,
            "createdBy": "GUI",
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "Q6tL31BrUl-vlY0yKsNSqA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": true,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:46Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": "*",
            "name": "/validation",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": "https",
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for updating url:
>|name|id|type|protocol|method|selfLink|clickjackingProtection|attackSignaturesCheck|createdBy|performStaging|isAllowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| /validation | Q6tL31BrUl-vlY0yKsNSqA | explicit | https | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0 | false | true | GUI | false | true | 2020-10-06T11:01:46Z |


### f5-asm-policy-urls-delete
***
Deletes a URL from a policy.


#### Base Command

`f5-asm-policy-urls-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| url_id | The ID of the URL. The ID or display name must be filled. Default is "None". | Optional | 
| url_name | The display name of the URL. The ID or display name must be filled. Default is "None". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Url.id | String | The ID of the URL. | 
| f5.Url.name | String | The name of the URL. | 
| f5.Url.description | String | A description of the URL. | 
| f5.Url.protocol | String | The protocol the URL uses. | 
| f5.Url.type | String | Whether the URL is explicit or wildcard. | 
| f5.Url.method | String | The allowed method \(or all\) of the URL. | 
| f5.Url.isAllowed | Boolean | Whether the URL is allowed. | 
| f5.Url.clickjackingProtection | Boolean | Whether clickjacking protection is enabled in the URL. | 
| f5.Url.performStaging | Boolean | Indicates whether the URL should be staged. | 
| f5.Url.mandatoryBody | Boolean | Whether a request body is mandatory. | 
| f5.Url.selfLink | String | The self link to the specific URL in the API. | 
| f5.Url.lastUpdateMicros | String | The datetime the last update was committed to the URL represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-urls-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA  url_name=/validation```

#### Context Example
```
{
    "f5": {
        "Url": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": false,
            "createdBy": "GUI",
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "Q6tL31BrUl-vlY0yKsNSqA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": true,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:46Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": "*",
            "name": "/validation",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": "https",
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting url:
>|name|id|type|protocol|method|selfLink|clickjackingProtection|attackSignaturesCheck|createdBy|performStaging|isAllowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| /validation | Q6tL31BrUl-vlY0yKsNSqA | explicit | https | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0 | false | true | GUI | false | true | 2020-10-06T11:01:46Z |


### f5-asm-policy-cookies-update
***
Updates a cookie object.


#### Base Command

`f5-asm-policy-cookies-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| cookie_id | The ID of the cookie. The ID or display name must be filled. Default is "None". | Optional | 
| cookie_name | The display name of the cookie. The ID or display name must be filled. Default is "None". | Optional | 
| perform_staging | Whether to stage the updated cookie. Default is "false". | Optional | 
| parameter_type | The type of the new parameter. Possible values are: "wildcard" and "explicit". Default is "wildcard". | Optional | 
| enforcement_type | The enforcement type. Possible values are: "allow" and "enforce".Default is "allow". | Optional | 
| attack_signatures_check | Whether attack signatures should be checked. Default is "true". If the enforcement type is set to "enforce", this field will not get any value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Cookies.name | String | The name of the cookie. | 
| f5.Cookies.id | String | The ID of the cookie. | 
| f5.Cookies.selfLink | String | The self link to the specific cookie. | 
| f5.Cookies.enforcementType | String | The enforcement type. | 
| f5.Cookies.performStaging | Boolean | Indicates whether the cookie should be staged. | 
| f5.Cookies.type | String | The type of the cookie. | 
| f5.Cookies.isBase64 | Boolean | Indicates if the cookie is encoded in base64. | 
| f5.Cookies.createdBy | String | Indicates who created the cookie. | 


#### Command Example
```!f5-asm-policy-cookies-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA cookie_name=new_cookie```

#### Context Example
```
{
    "f5": {
        "Cookies": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": "allow",
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "7t_U2dbYEAQp89Wp0m_QoA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": false,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:18Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "new_cookie",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "wildcard",
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for updating cookie: new_cookie
>|name|id|type|selfLink|enforcementType|isBase64|attackSignaturesCheck|createdBy|performStaging|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| new_cookie | 7t_U2dbYEAQp89Wp0m_QoA | wildcard | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0 | allow | false | true | GUI | false | 2020-10-06T11:01:18Z |


### f5-asm-policy-cookies-delete
***
Deletes a cookie.


#### Base Command

`f5-asm-policy-cookies-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| cookie_id | The ID of the cookie. The ID or display name must be filled. Default is "None". | Optional | 
| cookie_name | The display name of the cookie. The ID or display name must be filled. Default is "None". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Cookies.name | String | The name of the cookie. | 
| f5.Cookies.id | String | The ID of the cookie. | 
| f5.Cookies.selfLink | String | The self link to the specific cookie. | 
| f5.Cookies.enforcementType | String | The enforcement type. | 
| f5.Cookies.performStaging | Boolean | Indicates whether the cookie should be staged. | 
| f5.Cookies.type | String | The type of the cookie. | 
| f5.Cookies.isBase64 | Boolean | Indicates if the cookie is encoded in base64. | 
| f5.Cookies.createdBy | String | Indicates who created the cookie. | 


#### Command Example
```!f5-asm-policy-cookies-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA cookie_name=new_cookie```

#### Context Example
```
{
    "f5": {
        "Cookies": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": "allow",
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "7t_U2dbYEAQp89Wp0m_QoA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": false,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:18Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "new_cookie",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "wildcard",
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting cookie:
>|name|id|type|selfLink|enforcementType|isBase64|attackSignaturesCheck|createdBy|performStaging|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| new_cookie | 7t_U2dbYEAQp89Wp0m_QoA | wildcard | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0 | allow | false | true | GUI | false | 2020-10-06T11:01:18Z |


### f5-asm-policy-whitelist-ips-list
***
Lists all whitelisted IP addresses for a policy.


#### Base Command

`f5-asm-policy-whitelist-ips-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.WhitelistIP.id | String | The ID of the whitelisted IP address. | 
| f5.WhitelistIP.ipAddress | String | The whitelisted IP address. | 
| f5.WhitelistIP.ipMask | String | The subnet mask of the whitelisted IP address. | 
| f5.WhitelistIP.description | String | The description for the whitelisted IP address. | 
| f5.WhitelistIP.blockRequests | String | How or if the IP blocks requests. | 
| f5.WhitelistIP.ignoreAnomalies | Boolean | Whether to ignore anomalies. | 
| f5.WhitelistIP.neverLogRequests | Boolean | Whether to never log requests. | 
| f5.WhitelistIP.neverLearnRequests | Boolean | Whether to never learn requests. | 
| f5.WhitelistIP.trustedByPolicyBuilder | Boolean | Whether the IP is trusted by the builder. | 
| f5.WhitelistIP.selfLink | String | The self link to the specific whitelisted IP. | 
| f5.WhitelistIP.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-whitelist-ips-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "WhitelistIP": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "4CuqTmGkqfI01diFbc2PJQ",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "100.100.100.100",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:13:09Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/4CuqTmGkqfI01diFbc2PJQ?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": false,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "lbpOAL2E2f2C7qp7kiV3OA",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "20.20.20.20",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:13:38Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/lbpOAL2E2f2C7qp7kiV3OA?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": false,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "Uey6PzyJhbb6Qm-w0RD__Q",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "30.30.30.30",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T21:13:48Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/Uey6PzyJhbb6Qm-w0RD__Q?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": false,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "9lSC2hzsLvpsEgSTEpi4yw",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "11.22.33.44",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-09T15:15:56Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/9lSC2hzsLvpsEgSTEpi4yw?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": false,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "F2ZRy81hCYIAnYolA0fqzg",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "1.2.3.44",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-11T14:32:19Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": true,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/F2ZRy81hCYIAnYolA0fqzg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": false,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "6fatQ08fMtHzcywc4gQDJA",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "1.2.3.144",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-11T14:31:24Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": true,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/6fatQ08fMtHzcywc4gQDJA?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": true,
                "type": null,
                "valueType": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 list of all whitelist IPs:
>|id|selfLink|ipAddress|ipMask|blockRequests|ignoreAnomalies|neverLogRequests|neverLearnRequests|trustedByPolicyBuilder|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| 4CuqTmGkqfI01diFbc2PJQ | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/4CuqTmGkqfI01diFbc2PJQ?ver=15.1.0 | 100.100.100.100 | 255.255.255.255 | policy-default | false | false | false | false | 2020-08-05T21:13:09Z |
>| lbpOAL2E2f2C7qp7kiV3OA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/lbpOAL2E2f2C7qp7kiV3OA?ver=15.1.0 | 20.20.20.20 | 255.255.255.255 | policy-default | false | false | false | false | 2020-08-05T21:13:38Z |
>| Uey6PzyJhbb6Qm-w0RD__Q | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/Uey6PzyJhbb6Qm-w0RD__Q?ver=15.1.0 | 30.30.30.30 | 255.255.255.255 | policy-default | false | false | false | false | 2020-08-05T21:13:48Z |
>| 9lSC2hzsLvpsEgSTEpi4yw | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/9lSC2hzsLvpsEgSTEpi4yw?ver=15.1.0 | 11.22.33.44 | 255.255.255.255 | policy-default | false | false | false | false | 2020-08-09T15:15:56Z |
>| F2ZRy81hCYIAnYolA0fqzg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/F2ZRy81hCYIAnYolA0fqzg?ver=15.1.0 | 1.2.3.44 | 255.255.255.255 | policy-default | false | true | false | false | 2020-08-11T14:32:19Z |
>| 6fatQ08fMtHzcywc4gQDJA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/6fatQ08fMtHzcywc4gQDJA?ver=15.1.0 | 1.2.3.144 | 255.255.255.255 | policy-default | false | false | true | true | 2020-08-11T14:31:24Z |


### f5-asm-policy-whitelist-ips-add
***
Adds a new whitelisted IP address to a policy.


#### Base Command

`f5-asm-policy-whitelist-ips-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| ip_address | The new IP address. | Required | 
| ip_mask | Subnet mask for the new IP address. | Optional | 
| trusted_by_builder | Whether the IP address is trusted by the policy builder. | Optional | 
| ignore_brute_detection | Whether to ignore detections of brute force. | Optional | 
| description | Optional description for the new IP address. | Optional | 
| block_requests | The method of blocking requests. Possible values are: "policy-default", "never", and "always". Default is "policy-default". | Optional | 
| ignore_learning | Whether to ignore learning suggestions. | Optional | 
| never_log | Whether to never log from the IP address. | Optional | 
| ignore_intelligence | Whether to ignore intelligence gathered on the IP address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.WhitelistIP.id | String | ID of the whitelisted IP address. | 
| f5.WhitelistIP.ipAddress | String | The whitelisted IP address. | 
| f5.WhitelistIP.ipMask | String | The subnet mask of the whitelisted IP address. | 
| f5.WhitelistIP.description | String | A description for the whitelisted IP address. | 
| f5.WhitelistIP.blockRequests | String | How or if the IP blocks requests. | 
| f5.WhitelistIP.ignoreAnomalies | Boolean | Whether to ignore anomalies. | 
| f5.WhitelistIP.neverLogRequests | Boolean | Whether to never log requests. | 
| f5.WhitelistIP.neverLearnRequests | Boolean | Whether to never learn requests. | 
| f5.WhitelistIP.trustedByPolicyBuilder | Boolean | Whether the IP address is trusted by the builder. | 
| f5.WhitelistIP.selfLink | String | The self link to the specific whitelisted IP. | 
| f5.WhitelistIP.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-whitelist-ips-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA ip_address=1.2.3.4```

#### Context Example
```
{
    "f5": {
        "WhitelistIP": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": "policy-default",
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "pwbUREF-1u-BDw9MrdisOA",
            "ignoreAnomalies": false,
            "includeSubdomains": null,
            "ipAddress": "1.2.3.4",
            "ipMask": "255.255.255.255",
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:54Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": null,
            "neverLearnRequests": false,
            "neverLogRequests": false,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": false,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing whitelist IP:
>|id|selfLink|ipAddress|ipMask|blockRequests|ignoreAnomalies|neverLogRequests|neverLearnRequests|trustedByPolicyBuilder|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| pwbUREF-1u-BDw9MrdisOA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0 | 1.2.3.4 | 255.255.255.255 | policy-default | false | false | false | false | 2020-10-06T11:01:54Z |


### f5-asm-policy-whitelist-ips-update
***
Updates an existing whitelisted IP address.


#### Base Command

`f5-asm-policy-whitelist-ips-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| ip_id | The ID of the IP address. The ID or display name must be filled. Default is "None". | Optional | 
| ip_address | IP address | Required | 
| trusted_by_builder | Whether the IP address is trusted by the policy builder. The ID or display name must be filled. | Optional | 
| ignore_brute_detection | Whether to ignore detections of brute force. | Optional | 
| description | Optional description for the new IP address. | Optional | 
| block_requests | The method of blocking requests. Possible values are: "policy-default", "never", and "always". Default is "policy-default". | Optional | 
| ignore_learning | Whether to ignore learning suggestions. | Optional | 
| never_log | Whether to never log from the IP address. | Optional | 
| ignore_intelligence | Whether to ignore intelligence gathered on the IP address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.WhitelistIP.id | String | The ID of the whitelisted IP address. | 
| f5.WhitelistIP.ipAddress | String | The whitelisted IP address. | 
| f5.WhitelistIP.ipMask | String | The subnet mask of the whitelisted IP address. | 
| f5.WhitelistIP.description | String | A description for the whitelisted IP address. | 
| f5.WhitelistIP.blockRequests | String | How or if the IP address blocks requests. | 
| f5.WhitelistIP.ignoreAnomalies | Boolean | Whether to ignore anomalies. | 
| f5.WhitelistIP.neverLogRequests | Boolean | Whether to never log requests. | 
| f5.WhitelistIP.neverLearnRequests | Boolean | Whether to never learn requests. | 
| f5.WhitelistIP.trustedByPolicyBuilder | Boolean | Whether the IP address is trusted by the builder. | 
| f5.WhitelistIP.selfLink | String | The self link to the specific whitelisted IP. | 
| f5.WhitelistIP.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-whitelist-ips-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA ip_address=1.2.3.4```

#### Context Example
```
{
    "f5": {
        "WhitelistIP": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": "policy-default",
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "pwbUREF-1u-BDw9MrdisOA",
            "ignoreAnomalies": false,
            "includeSubdomains": null,
            "ipAddress": "1.2.3.4",
            "ipMask": "255.255.255.255",
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:54Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": null,
            "neverLearnRequests": false,
            "neverLogRequests": false,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": false,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing whitelist IP:
>|id|selfLink|ipAddress|ipMask|blockRequests|ignoreAnomalies|neverLogRequests|neverLearnRequests|trustedByPolicyBuilder|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| pwbUREF-1u-BDw9MrdisOA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0 | 1.2.3.4 | 255.255.255.255 | policy-default | false | false | false | false | 2020-10-06T11:01:54Z |


### f5-asm-policy-whitelist-ips-delete
***
Deletes an existing whitelisted IP address from a policy.


#### Base Command

`f5-asm-policy-whitelist-ips-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| ip_id | The ID of the IP address. The ID or display name must be filled. Default is "None". | Optional | 
| ip_address | IP address | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.WhitelistIP.id | String | The ID of the whitelisted IP address. | 
| f5.WhitelistIP.ipAddress | String | The whitelisted IP address. | 
| f5.WhitelistIP.ipMask | String | The subnet mask of the whitelisted IP address. | 
| f5.WhitelistIP.description | String | A description for the whitelisted IP address. | 
| f5.WhitelistIP.blockRequests | String | How or if the IP address blocks requests. | 
| f5.WhitelistIP.ignoreAnomalies | Boolean | Whether to ignore anomalies. | 
| f5.WhitelistIP.neverLogRequests | Boolean | Whether to never log requests. | 
| f5.WhitelistIP.neverLearnRequests | Boolean | Whether to never learn requests. | 
| f5.WhitelistIP.trustedByPolicyBuilder | Boolean | Whether the IP address is trusted by the builder. | 
| f5.WhitelistIP.selfLink | String | The self link to the specific whitelisted IP. | 
| f5.WhitelistIP.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-whitelist-ips-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA ip_address=1.2.3.4```

#### Context Example
```
{
    "f5": {
        "WhitelistIP": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": "policy-default",
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "pwbUREF-1u-BDw9MrdisOA",
            "ignoreAnomalies": false,
            "includeSubdomains": null,
            "ipAddress": "1.2.3.4",
            "ipMask": "255.255.255.255",
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:01:54Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": null,
            "neverLearnRequests": false,
            "neverLogRequests": false,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": false,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing whitelist IP:
>|id|selfLink|ipAddress|ipMask|blockRequests|ignoreAnomalies|neverLogRequests|neverLearnRequests|trustedByPolicyBuilder|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| pwbUREF-1u-BDw9MrdisOA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0 | 1.2.3.4 | 255.255.255.255 | policy-default | false | false | false | false | 2020-10-06T11:01:54Z |


### f5-asm-policy-signatures-list
***
Lists all signatures for a specified policy.


#### Base Command

`f5-asm-policy-signatures-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Signatures.id | String | The ID of the signature. | 
| f5.Signatures.selfLink | String | The self link to the specific signature. | 
| f5.Signatures.performStaging | Boolean | Indicates whether the signature should be staged. | 
| f5.Signatures.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
``` ```

#### Human Readable Output



### f5-asm-policy-parameters-list
***
Lists all policy parameters.


#### Base Command

`f5-asm-policy-parameters-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Parameter.id | String | The ID of the parameter. | 
| f5.Parameter.name | String | The display name of the parameter. | 
| f5.Parameter.type | String | The type of parameter \(explicit / wildcard\). | 
| f5.Parameter.selfLink | String | The self link to the specific parameter. | 
| f5.Parameter.isBase64 | Boolean | Indicates if the parameter is encoded in base64. | 
| f5.Parameter.performStaging | Boolean | Indicates whether the parameter should be staged. | 
| f5.Parameter.dataType | String | The type of data given in the parameter. | 
| f5.Parameter.valueType | String | The type of values given in the parameter. | 
| f5.Parameter.mandatory | Boolean | Whether the parameter is mandatory. | 
| f5.Parameter.isCookie | Boolean | Whether the parameter is located in the cookie. | 
| f5.Parameter.isHeader | Boolean | Whether the parameter is located in the header. | 
| f5.Parameter.createdBy | String | Indicates who created the parameter. | 
| f5.Parameter.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-parameters-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "Parameter": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": "alpha-numeric",
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "lyM6dyIqaEw9oARv5V8cKg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "isCookie": false,
                "isHeader": false,
                "lastUpdateMicros": "2020-09-22T14:37:17Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "new_parameter",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/lyM6dyIqaEw9oARv5V8cKg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "wildcard",
                "valueType": "user-input"
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "dataType": "alpha-numeric",
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "N_a3D1S7OKDehYEPb-mgCg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "isCookie": false,
                "isHeader": false,
                "lastUpdateMicros": "2020-08-23T10:24:11Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": "*",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/N_a3D1S7OKDehYEPb-mgCg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": "wildcard",
                "valueType": "user-input"
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 list of all parameters:
>|name|id|type|selfLink|attackSignaturesCheck|isBase64|dataType|valueType|isCookie|isHeader|performStaging|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| new_parameter | lyM6dyIqaEw9oARv5V8cKg | wildcard | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/lyM6dyIqaEw9oARv5V8cKg?ver=15.1.0 | true | false | alpha-numeric | user-input | false | false | false | GUI | 2020-09-22T14:37:17Z |
>| * | N_a3D1S7OKDehYEPb-mgCg | wildcard | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/N_a3D1S7OKDehYEPb-mgCg?ver=15.1.0 | true | false | alpha-numeric | user-input | false | false | false | GUI | 2020-08-23T10:24:11Z |


### f5-asm-policy-parameters-add
***
Adds a new parameter to a policy.


#### Base Command

`f5-asm-policy-parameters-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| param_type | The type of the new parameter. Possible values are: "wildcard" and "explicit". | Optional | 
| name | The display name of the new parameter. | Required | 
| value_type | The type of value passed to the parameter. Possible values are: "user-input", "json", "static-content", "auto-detect", and "xml". | Optional | 
| param_location | The location of the parameter. Possible values are: "any", "query", "form-data", "path", "header",  and "cookie". | Optional | 
| mandatory | Whether the parameter is mandatory. | Optional | 
| perform_staging | Whether to stage the parameter. | Optional | 
| sensitive | Whether the parameter is sensitive. (Whether values should be masked in logs.) | Optional | 
| allow_empty | Whether the parameter allows empty values. | Optional | 
| allow_repeated | Whether the parameter allows repeated values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Parameter.id | String | The ID of the parameter. | 
| f5.Parameter.name | String | The display name of the parameter. | 
| f5.Parameter.type | String | The type of parameter \(explicit / wildcard\). | 
| f5.Parameter.selfLink | String | The self link to the specific parameter. | 
| f5.Parameter.isBase64 | Boolean | Indicates if the parameter is encoded in base64. | 
| f5.Parameter.performStaging | Boolean | Indicates whether the parameter should be staged. | 
| f5.Parameter.dataType | String | The type of data given in the parameter. | 
| f5.Parameter.valueType | String | The type of values given in the parameter. | 
| f5.Parameter.mandatory | Boolean | Whether the parameter is mandatory. | 
| f5.Parameter.isCookie | Boolean | Whether the parameter is located in the cookie. | 
| f5.Parameter.isHeader | Boolean | Whether the parameter is located in the header. | 
| f5.Parameter.createdBy | String | Indicates who created the parameter. | 
| f5.Parameter.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-parameters-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA name=test_policy_parameter```

#### Context Example
```
{
    "f5": {
        "Parameter": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "dataType": "alpha-numeric",
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "Wm_Vq93ZrYML8FfDJqGSIw",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": false,
            "isCookie": false,
            "isHeader": false,
            "lastUpdateMicros": "2020-10-06T11:02:03Z",
            "mandatory": false,
            "metacharElementCheck": null,
            "method": null,
            "name": "test_policy_parameter",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/Wm_Vq93ZrYML8FfDJqGSIw?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": "user-input"
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding parameter:
>|name|id|type|selfLink|isBase64|dataType|attackSignaturesCheck|isBase64|valueType|mandatory|isCookie|isHeader|createdBy|performStaging|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| test_policy_parameter | Wm_Vq93ZrYML8FfDJqGSIw | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/Wm_Vq93ZrYML8FfDJqGSIw?ver=15.1.0 | false | alpha-numeric | true | false | user-input | false | false | false | GUI | false | GUI | 2020-10-06T11:02:03Z |


### f5-asm-policy-parameters-update
***
Updates an existing policy parameter.


#### Base Command

`f5-asm-policy-parameters-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| parameter_id | The ID of the parameter. The ID or display name must be filled. Default is "None". | Optional | 
| parameter_name | The display name of the parameter. The ID or display name must be filled. | Required | 
| value_type | The type of value passed to the parameter. Possible values are: "user-input", "array", "dynamic", "ignore", "json", "static", "auto", and "xml". | Optional | 
| param_location | The location of the parameter. Possible values are: "any", "query", "form-data", "path", "header",  and "cookie". | Optional | 
| mandatory | Whether the parameter is mandatory. | Optional | 
| perform_staging | Whether to stage the parameter. | Optional | 
| sensitive | Whether the parameter is sensitive. (Whether values should be masked in logs.) | Optional | 
| allow_empty | Whether the parameter allows empty values. | Optional | 
| allow_repeated | Whether the parameter allows repeated values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Parameter.id | String | The ID of the parameter. | 
| f5.Parameter.name | String | The display name of the parameter. | 
| f5.Parameter.type | String | The type of parameter \(explicit / wildcard\). | 
| f5.Parameter.selfLink | String | The self link to the specific parameter. | 
| f5.Parameter.isBase64 | Boolean | Indicates if the parameter is encoded in base64. | 
| f5.Parameter.performStaging | Boolean | Indicates whether the parameter should be staged. | 
| f5.Parameter.dataType | String | The type of data given in the parameter. | 
| f5.Parameter.valueType | String | The type of values given in the parameter. | 
| f5.Parameter.mandatory | Boolean | Whether the parameter is mandatory. | 
| f5.Parameter.isCookie | Boolean | Whether the parameter is located in the cookie. | 
| f5.Parameter.isHeader | Boolean | Whether the parameter is located in the header. | 
| f5.Parameter.createdBy | String | Indicates who created the parameter. | 
| f5.Parameter.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-parameters-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA parameter_name=test_policy_parameter```

#### Context Example
```
{
    "f5": {
        "Parameter": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "dataType": "alpha-numeric",
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "Wm_Vq93ZrYML8FfDJqGSIw",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": false,
            "isCookie": false,
            "isHeader": false,
            "lastUpdateMicros": "2020-10-06T11:02:03Z",
            "mandatory": false,
            "metacharElementCheck": null,
            "method": null,
            "name": "test_policy_parameter",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/Wm_Vq93ZrYML8FfDJqGSIw?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": "user-input"
        }
    }
}
```

#### Human Readable Output

>### f5 data for updating parameter:
>|name|id|type|selfLink|isBase64|dataType|attackSignaturesCheck|isBase64|valueType|mandatory|isCookie|isHeader|createdBy|performStaging|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| test_policy_parameter | Wm_Vq93ZrYML8FfDJqGSIw | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/Wm_Vq93ZrYML8FfDJqGSIw?ver=15.1.0 | false | alpha-numeric | true | false | user-input | false | false | false | GUI | false | GUI | 2020-10-06T11:02:03Z |


### f5-asm-policy-parameters-delete
***
Deletes an existing policy parameter.


#### Base Command

`f5-asm-policy-parameters-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| parameter_id | The ID of the parameter. The ID or display name must be filled. Default is "None". | Optional | 
| parameter_name | The display name of the parameter. ID or display name must be filled. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Parameter.id | String | The ID of the parameter. | 
| f5.Parameter.name | String | The display name of the parameter. | 
| f5.Parameter.type | String | The type of parameter \(explicit / wildcard\). | 
| f5.Parameter.selfLink | String | The self link to the specific parameter. | 
| f5.Parameter.isBase64 | Boolean | Indicates if the parameter is encoded in base64. | 
| f5.Parameter.performStaging | Boolean | Indicates whether the parameter should be staged. | 
| f5.Parameter.dataType | String | The type of data given in the parameter. | 
| f5.Parameter.valueType | String | The type of values given in the parameter. | 
| f5.Parameter.mandatory | Boolean | Whether the parameter is mandatory. | 
| f5.Parameter.isCookie | Boolean | Whether the parameter is located in the cookie. | 
| f5.Parameter.isHeader | Boolean | Whether the parameter is located in the header. | 
| f5.Parameter.createdBy | String | Indicates who created the parameter. | 
| f5.Parameter.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-parameters-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA parameter_name=test_policy_parameter```

#### Context Example
```
{
    "f5": {
        "Parameter": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "dataType": "alpha-numeric",
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "Wm_Vq93ZrYML8FfDJqGSIw",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": false,
            "isCookie": false,
            "isHeader": false,
            "lastUpdateMicros": "2020-10-06T11:02:03Z",
            "mandatory": false,
            "metacharElementCheck": null,
            "method": null,
            "name": "test_policy_parameter",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/Wm_Vq93ZrYML8FfDJqGSIw?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null,
            "valueType": "user-input"
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting parameter:
>|name|id|type|selfLink|isBase64|dataType|attackSignaturesCheck|isBase64|valueType|mandatory|isCookie|isHeader|createdBy|performStaging|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| test_policy_parameter | Wm_Vq93ZrYML8FfDJqGSIw | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/parameters/Wm_Vq93ZrYML8FfDJqGSIw?ver=15.1.0 | false | alpha-numeric | true | false | user-input | false | false | false | GUI | false | GUI | 2020-10-06T11:02:03Z |


### f5-asm-policy-gwt-profiles-list
***
Lists all GWT profiles in a policy.


#### Base Command

`f5-asm-policy-gwt-profiles-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.GWTProfile.id | String | The ID of the GWT profile. | 
| f5.GWTProfile.name | String | The display name of the GWT profile. | 
| f5.GWTProfile.description | String | A description of the GWT profile. | 
| f5.GWTProfile.isDefault | Boolean | Whether the GWT profile is the default profile. | 
| f5.GWTProfile.attackSignaturesCheck | Boolean | Whether the GWT profile should check for attack signatures. | 
| f5.GWTProfile.isReferenced | Boolean | Whether the GWT profile is referenced. | 
| f5.GWTProfile.metacharElementCheck | Boolean | Whether the GWT profile should check for metachar elements. | 


#### Command Example
```!f5-asm-policy-gwt-profiles-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "GWTProfile": {
            "actAsMethod": null,
            "active": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "Default GWT Profile",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "pKOP2_h7ezXmyZ-mE3cPnw",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-08-05T20:58:49Z",
            "mandatory": null,
            "mandatoryBody": null,
            "metacharElementCheck": true,
            "method": null,
            "name": "Default",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "protocol": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/gwt-profiles/pKOP2_h7ezXmyZ-mE3cPnw?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 list of all GWT Profiles:
>|name|id|selfLink|description|attackSignaturesCheck|metacharElementCheck|lastUpdateMicros|
>|---|---|---|---|---|---|---|
>| Default | pKOP2_h7ezXmyZ-mE3cPnw | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/gwt-profiles/pKOP2_h7ezXmyZ-mE3cPnw?ver=15.1.0 | Default GWT Profile | true | true | 2020-08-05T20:58:49Z |


### f5-asm-policy-gwt-profiles-add
***
Adds a new GWT profile to a policy.


#### Base Command

`f5-asm-policy-gwt-profiles-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| name | The display name of the profile. | Required | 
| description | Optional description for the profile. | Optional | 
| maximum_value_len | The maximum length for a value in the profile. Default is "any". | Optional | 
| maximum_total_len | The maximum length of all GWT data. Default is "any". | Optional | 
| tolerate_parsing_warnings | Whether the profile should tolerate parsing warnings. | Optional | 
| check_signatures | Whether the profile should check for attack signatures. | Optional | 
| check_metachars | Whether the profile should check for metachar elements. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.GWTProfile.id | String | The ID of the GWT profile. | 
| f5.GWTProfile.name | String | The display name of the GWT profile. | 
| f5.GWTProfile.description | String | A description of the GWT profile. | 
| f5.GWTProfile.isDefault | Boolean | Whether the GWT profile is the default profile. | 
| f5.GWTProfile.attackSignaturesCheck | Boolean | Whether the GWT profile should check for attack signatures. | 
| f5.GWTProfile.isReferenced | Boolean | Whether the GWT profile is referenced. | 
| f5.GWTProfile.metacharElementCheck | Boolean | Whether the GWT profile should check for metachar elements. | 


#### Command Example
```!f5-asm-policy-gwt-profiles-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA name=test_gwt_profile```

#### Context Example
```
{
    "f5": {
        "GWTProfile": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "R8SpevWA8hLFJ7dH2u6NqQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:12Z",
            "mandatory": null,
            "metacharElementCheck": false,
            "method": null,
            "name": "test_gwt_profile",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/gwt-profiles/R8SpevWA8hLFJ7dH2u6NqQ?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding GWT profile:
>|name|id|selfLink|attackSignaturesCheck|metacharElementCheck|lastUpdateMicros|
>|---|---|---|---|---|---|
>| test_gwt_profile | R8SpevWA8hLFJ7dH2u6NqQ | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/gwt-profiles/R8SpevWA8hLFJ7dH2u6NqQ?ver=15.1.0 | true | false | 2020-10-06T11:02:12Z |


### f5-asm-policy-gwt-profiles-update
***
Updates an existing GWT profile


#### Base Command

`f5-asm-policy-gwt-profiles-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| gwt_profile_id | The ID of the GWT profile. The ID or display name must be filled. Default is "None". | Optional | 
| gwt_profile_name | The display name of the GWT profile. The ID or display name must be filled. | Required | 
| description | Optional description for the profile. | Optional | 
| maximum_value_len | The maximum length for a value in the profile. Default is "any". | Optional | 
| maximum_total_len | The maximum length of all GWT data. Default is "any". | Optional | 
| tolerate_parsing_warnings | Whether to tolerate parsing warnings. | Optional | 
| check_signatures | Whether the profile should check for attack signatures. | Optional | 
| check_metachars | Whether the profile should check for metachar elements. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.GWTProfile.id | String | The ID of the GWT profile. | 
| f5.GWTProfile.name | String | The display name of the GWT profile. | 
| f5.GWTProfile.description | String | A description of the GWT profile. | 
| f5.GWTProfile.isDefault | Boolean | Whether the GWT profile is the default profile. | 
| f5.GWTProfile.attackSignaturesCheck | Boolean | Whether the GWT profile should check for attack signatures. | 
| f5.GWTProfile.isReferenced | Boolean | Whether the GWT profile is referenced. | 
| f5.GWTProfile.metacharElementCheck | Boolean | Whether the GWT profile should check for metachar elements. | 


#### Command Example
```!f5-asm-policy-gwt-profiles-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA gwt_profile_name=test_gwt_profile```

#### Context Example
```
{
    "f5": {
        "GWTProfile": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "R8SpevWA8hLFJ7dH2u6NqQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:12Z",
            "mandatory": null,
            "metacharElementCheck": false,
            "method": null,
            "name": "test_gwt_profile",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/gwt-profiles/R8SpevWA8hLFJ7dH2u6NqQ?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for updating GWT profile:
>|name|id|selfLink|attackSignaturesCheck|metacharElementCheck|lastUpdateMicros|
>|---|---|---|---|---|---|
>| test_gwt_profile | R8SpevWA8hLFJ7dH2u6NqQ | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/gwt-profiles/R8SpevWA8hLFJ7dH2u6NqQ?ver=15.1.0 | true | false | 2020-10-06T11:02:12Z |


### f5-asm-policy-gwt-profiles-delete
***
Deletes an existing GWT profile.


#### Base Command

`f5-asm-policy-gwt-profiles-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| gwt_profile_id | The ID of the GWT profile. The ID or display name must be filled. Default is "None". | Optional | 
| gwt_profile_name | The display name of the GWT profile. The ID or display name must be filled. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.GWTProfile.id | String | The ID of the GWT profile. | 
| f5.GWTProfile.name | String | The display name of the GWT profile. | 
| f5.GWTProfile.description | String | A description of the GWT profile. | 
| f5.GWTProfile.isDefault | Boolean | Whether the GWT profile is the default profile. | 
| f5.GWTProfile.attackSignaturesCheck | Boolean | Whether the GWT profile should check for attack signatures. | 
| f5.GWTProfile.isReferenced | Boolean | Whether the GWT profile is referenced. | 
| f5.GWTProfile.metacharElementCheck | Boolean | Whether the GWT profile should check for metachar elements. | 


#### Command Example
```!f5-asm-policy-gwt-profiles-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA gwt_profile_name=test_gwt_profile```

#### Context Example
```
{
    "f5": {
        "GWTProfile": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "R8SpevWA8hLFJ7dH2u6NqQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:12Z",
            "mandatory": null,
            "metacharElementCheck": false,
            "method": null,
            "name": "test_gwt_profile",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/gwt-profiles/R8SpevWA8hLFJ7dH2u6NqQ?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting GWT profile:
>|name|id|selfLink|attackSignaturesCheck|metacharElementCheck|lastUpdateMicros|
>|---|---|---|---|---|---|
>| test_gwt_profile | R8SpevWA8hLFJ7dH2u6NqQ | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/gwt-profiles/R8SpevWA8hLFJ7dH2u6NqQ?ver=15.1.0 | true | false | 2020-10-06T11:02:12Z |


### f5-asm-policy-json-profiles-list
***
Lists all JSON profiles in a policy.


#### Base Command

`f5-asm-policy-json-profiles-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.JSONProfile.id | String | The ID of JSON profile. | 
| f5.JSONProfile.name | String | The display name of the JSON profile. | 
| f5.JSONProfile.description | String | A description of he JSON profile. | 
| f5.JSONProfile.isDefault | Boolean | Whether the JSON profile is the default profile. | 
| f5.JSONProfile.attackSignaturesCheck | Boolean | Whether the JSON profile should check for attack signatures. | 
| f5.JSONProfile.isReferenced | Boolean | Whether the JSON profile is referenced. | 
| f5.JSONProfile.metacharElementCheck | Boolean | Whether the JSON profile should check for metachar elements. | 
| f5.JSONProfile.hasValidationFiles | Boolean | Whether the JSON profile has validation files. | 
| f5.JSONProfile.selfLink | String | The self link to the specific profile. | 
| f5.JSONProfile.lastUpdate | String | The time the last update was made to the profile. | 


#### Command Example
```!f5-asm-policy-json-profiles-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "JSONProfile": {
            "actAsMethod": null,
            "active": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "Default JSON Profile",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": false,
            "id": "X8FbXF48VWJ5Tecp5ATd4A",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-08-05T20:58:49Z",
            "mandatory": null,
            "mandatoryBody": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "Default",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "protocol": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/json-profiles/X8FbXF48VWJ5Tecp5ATd4A?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 list of all JSON Profiles:
>|name|id|selfLink|description|hasValidationFiles|lastUpdateMicros|
>|---|---|---|---|---|---|
>| Default | X8FbXF48VWJ5Tecp5ATd4A | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/json-profiles/X8FbXF48VWJ5Tecp5ATd4A?ver=15.1.0 | Default JSON Profile | false | 2020-08-05T20:58:49Z |


### f5-asm-policy-json-profiles-add
***
Adds a new JSON profile to a policy.


#### Base Command

`f5-asm-policy-json-profiles-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| name | The display name of the new profile. | Required | 
| description | Optional description for the JSON profile. | Optional | 
| maximum_total_len | The maximum total length of the JSON data. Default is "any". | Optional | 
| maximum_value_len | The maximum length for a single value. Default is "any". | Optional | 
| max_structure_depth | The maximum structure depth. Default is "any". | Optional | 
| max_array_len | The maximum JSON array length. Default is "any". | Optional | 
| tolerate_parsing_warnings | Whether the profile should tolerate JSON parsing warnings. | Optional | 
| parse_parameters | Whether the profile should handle JSON values as parameters. | Optional | 
| check_signatures | Whether the profile should check for attack signatures. | Optional | 
| check_metachars | Whether the profile should check for metachar elements. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.JSONProfile.id | String | The ID of the JSON profile. | 
| f5.JSONProfile.name | String | The display name of the JSON profile. | 
| f5.JSONProfile.description | String | A description of the JSON profile. | 
| f5.JSONProfile.isDefault | Boolean | Whether the JSON profile is the default profile. | 
| f5.JSONProfile.attackSignaturesCheck | Boolean | Whether the JSON profile should check for attack signatures. | 
| f5.JSONProfile.isReferenced | Boolean | Whether the JSON profile is referenced. | 
| f5.JSONProfile.metacharElementCheck | Boolean | Whether the JSON profile should check for metachar elements. | 
| f5.JSONProfile.hasValidationFiles | Boolean | Whether the JSON profile has validation files. | 
| f5.JSONProfile.selfLink | String | The self link to the specific profile. | 
| f5.JSONProfile.lastUpdate | String | The time the last update was made to the profile. | 


#### Command Example
```!f5-asm-policy-json-profiles-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA name=test_json_profile```

#### Context Example
```
{
    "f5": {
        "JSONProfile": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": false,
            "id": "Mv3RpN8obPoe5IW-wdcdzA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:22Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "test_json_profile",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/json-profiles/Mv3RpN8obPoe5IW-wdcdzA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding JSON profile:
>|name|id|selfLink|hasValidationFiles|lastUpdateMicros|
>|---|---|---|---|---|
>| test_json_profile | Mv3RpN8obPoe5IW-wdcdzA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/json-profiles/Mv3RpN8obPoe5IW-wdcdzA?ver=15.1.0 | false | 2020-10-06T11:02:22Z |


### f5-asm-policy-json-profiles-update
***
Updates an existing JSON profile.


#### Base Command

`f5-asm-policy-json-profiles-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| json_id | The ID of the JSON profile. The ID or display name must be filled. Default is "None". | Optional | 
| json_name | The display name of the JSON profile. The ID or display name must be filled. | Required | 
| description | Optional description for the JSON profile | Optional | 
| maximum_total_len | The maximum total length of JSON data. Default is "any". | Optional | 
| maximum_value_len | The maximum length for a single value. Default is "any". | Optional | 
| max_structure_depth | The maximum structure depth. Default is "any". | Optional | 
| max_array_len | The maximum JSON array length. Default is "any". | Optional | 
| tolerate_parsing_warnings | Whether the profile should tolerate JSON parsing warnings. | Optional | 
| parse_parameters | Whether the profile should handle JSON values as parameters. | Optional | 
| check_signatures | Whether the profile should check for attack signatures. | Optional | 
| check_metachars | Whether the profile should check for metachar elements. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.JSONProfile.id | String | The ID of the JSON profile. | 
| f5.JSONProfile.name | String | The display name of the JSON profile. | 
| f5.JSONProfile.description | String | A description of the JSON profile. | 
| f5.JSONProfile.isDefault | Boolean | Whether the JSON profile is the default profile. | 
| f5.JSONProfile.attackSignaturesCheck | Boolean | Whether the JSON profile should check for attack signatures. | 
| f5.JSONProfile.isReferenced | Boolean | Whether the JSON profile is referenced. | 
| f5.JSONProfile.metacharElementCheck | Boolean | Whether the JSON profile should check for metachar elements. | 
| f5.JSONProfile.hasValidationFiles | Boolean | Whether the JSON profile has validation files. | 
| f5.JSONProfile.selfLink | String | The self link to the specific profile. | 
| f5.JSONProfile.lastUpdate | String | The time the last update was made to the profile. | 


#### Command Example
```!f5-asm-policy-json-profiles-update policy_md5=kpD2qFaUlGAbw8RhN5IFQA json_name=test_json_profile```

#### Context Example
```
{
    "f5": {
        "JSONProfile": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "any",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": false,
            "id": "Mv3RpN8obPoe5IW-wdcdzA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:24Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "test_json_profile",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/json-profiles/Mv3RpN8obPoe5IW-wdcdzA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for updating JSON profile:
>|name|id|selfLink|description|hasValidationFiles|lastUpdateMicros|
>|---|---|---|---|---|---|
>| test_json_profile | Mv3RpN8obPoe5IW-wdcdzA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/json-profiles/Mv3RpN8obPoe5IW-wdcdzA?ver=15.1.0 | any | false | 2020-10-06T11:02:24Z |


### f5-asm-policy-json-profiles-delete
***
Deletes an existing JSON profile from a policy


#### Base Command

`f5-asm-policy-json-profiles-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| json_id | The ID of the JSON profile. The ID or display name must be filled. Default is "None". | Optional | 
| json_name | The display name of the JSON profile. The ID or display name must be filled. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.JSONProfile.id | String | The ID of the JSON profile. | 
| f5.JSONProfile.name | String | The display name of the JSON profile. | 
| f5.JSONProfile.description | String | A description of the JSON profile. | 
| f5.JSONProfile.isDefault | Boolean | Whether the JSON profile is the default profile. | 
| f5.JSONProfile.attackSignaturesCheck | Boolean | Whether the JSON profile should check for attack signatures. | 
| f5.JSONProfile.isReferenced | Boolean | Whether the JSON profile is referenced. | 
| f5.JSONProfile.metacharElementCheck | Boolean | Whether the JSON profile should check for metachar elements. | 
| f5.JSONProfile.hasValidationFiles | Boolean | Whether the JSON profile has validation files. | 
| f5.JSONProfile.selfLink | String | The self link to the specific profile. | 
| f5.JSONProfile.lastUpdate | String | The time the last update was made to the profile. | 


#### Command Example
```!f5-asm-policy-json-profiles-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA json_name=test_json_profile```

#### Context Example
```
{
    "f5": {
        "JSONProfile": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "any",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": false,
            "id": "Mv3RpN8obPoe5IW-wdcdzA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:24Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": "test_json_profile",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/json-profiles/Mv3RpN8obPoe5IW-wdcdzA?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting JSON profile:
>|name|id|selfLink|description|hasValidationFiles|lastUpdateMicros|
>|---|---|---|---|---|---|
>| test_json_profile | Mv3RpN8obPoe5IW-wdcdzA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/json-profiles/Mv3RpN8obPoe5IW-wdcdzA?ver=15.1.0 | any | false | 2020-10-06T11:02:24Z |


### f5-asm-policy-xml-profiles-list
***
Lists all XML profiles in a policy.


#### Base Command

`f5-asm-policy-xml-profiles-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.XMLProfile.id | String | The ID of the XML profile | 
| f5.XMLProfile.name | String | The display name of the XML profile. | 
| f5.XMLProfile.description | String | A description of the XML profile. | 
| f5.XMLProfile.isDefault | Boolean | Whether the XML profile is the default profile. | 
| f5.XMLProfile.attackSignaturesCheck | Boolean | Whether the XML profile should check for attack signatures. | 
| f5.XMLProfile.followSchemaLinks | Boolean | Whether the profile should follow schema links. | 
| f5.XMLProfile.metacharElementCheck | Boolean | Whether the XML profile should check for metachar elements. | 
| f5.XMLProfile.metacharAttributeCheck | Boolean | Whether the profile should check for metachar attributes. | 
| f5.XMLProfile.isReferenced | Boolean | Whether the XML profile is referenced. | 
| f5.XMLProfile.enableWSS | Boolean | Whether the web service security should be enabled. | 
| f5.XMLProfile.hasValidationFiles | Boolean | Whether the XML profile has validation files. | 
| f5.XMLProfile.selfLink | String | The self link to the specific profile. | 
| f5.XMLProfile.lastUpdate | String | The time the last update was made to the profile. | 


#### Command Example
```!f5-asm-policy-xml-profiles-list policy_md5=kpD2qFaUlGAbw8RhN5IFQA```

#### Context Example
```
{
    "f5": {
        "XMLProfile": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": "",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": true,
                "hasValidationFiles": null,
                "id": "8pDEkwo33PlYf2EbTpt-3g",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-09-08T17:36:48Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": false,
                "method": null,
                "name": "new_xml_profile",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/8pDEkwo33PlYf2EbTpt-3g?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": true,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": "Default XML Profile",
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": false,
                "hasValidationFiles": null,
                "id": "jwQd_XYZPfNGYnc3l7P4Pg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-05T20:58:51Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": false,
                "method": null,
                "name": "Default",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg?ver=15.1.0",
                "serverTechnologyName": null,
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 list of all XML Profiles:
>|name|id|selfLink|description|attackSignaturesCheck|metacharElementCheck|followSchemaLinks|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|
>| new_xml_profile | 8pDEkwo33PlYf2EbTpt-3g | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/8pDEkwo33PlYf2EbTpt-3g?ver=15.1.0 |  | true | false | true | 2020-09-08T17:36:48Z |
>| Default | jwQd_XYZPfNGYnc3l7P4Pg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/jwQd_XYZPfNGYnc3l7P4Pg?ver=15.1.0 | Default XML Profile | true | false | false | 2020-08-05T20:58:51Z |


### f5-asm-policy-xml-profiles-add
***
Adds a new XML profile to a policy.


#### Base Command

`f5-asm-policy-xml-profiles-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| name | The display name of the profile to add. | Required | 
| description | Optional description for the profile. | Optional | 
| check_signatures | Whether the profile should check for attack signatures. | Optional | 
| check_metachar_elements | Whether to check for metachar elements. | Optional | 
| check_metachar_attributes | Whether to check for metachar attributes. | Optional | 
| enable_wss | Whether to enable web services securities. | Optional | 
| inspect_soap | Whether to inspect SOAP attachments. | Optional | 
| follow_links | Whether to follow schema links. | Optional | 
| use_xml_response | Whether to use the XML response page. | Optional | 
| allow_cdata | Whether to allow CDATA. | Optional | 
| allow_dtds | Whether to allow DTDs. | Optional | 
| allow_external_ref | Whether to allow external references. | Optional | 
| allow_processing_instructions | Whether to allow processing instructions. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.XMLProfile.id | String | The ID of the XML profile. | 
| f5.XMLProfile.name | String | The display name of the XML profile. | 
| f5.XMLProfile.description | String | A description of the XML profile. | 
| f5.XMLProfile.isDefault | Boolean | Whether the XML profile is the default profile. | 
| f5.XMLProfile.attackSignaturesCheck | Boolean | Whether the XML profile should check for attack signatures. | 
| f5.XMLProfile.followSchemaLinks | Boolean | Whether the profile should follow schema links. | 
| f5.XMLProfile.metacharElementCheck | Boolean | Whether the XML profile should check for metachar elements. | 
| f5.XMLProfile.metacharAttributeCheck | Boolean | Whether the profile should check for metachar attributes. | 
| f5.XMLProfile.isReferenced | Boolean | Whether the XML profile is referenced. | 
| f5.XMLProfile.enableWSS | Boolean | Whether the web service security should be enabled. | 
| f5.XMLProfile.hasValidationFiles | Boolean | Whether the XML profile has validation files. | 
| f5.XMLProfile.selfLink | String | The self link to the specific profile. | 
| f5.XMLProfile.lastUpdate | String | The time the last update was made to the profile. | 


#### Command Example
```!f5-asm-policy-xml-profiles-add policy_md5=kpD2qFaUlGAbw8RhN5IFQA name=test_xml_profile```

#### Context Example
```
{
    "f5": {
        "XMLProfile": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": true,
            "hasValidationFiles": null,
            "id": "zfebD7S9AIziPBRYkAkDww",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:36Z",
            "mandatory": null,
            "metacharElementCheck": false,
            "method": null,
            "name": "test_xml_profile",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/zfebD7S9AIziPBRYkAkDww?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding XML profile:
>|name|id|selfLink|attackSignaturesCheck|metacharElementCheck|followSchemaLinks|lastUpdateMicros|
>|---|---|---|---|---|---|---|
>| test_xml_profile | zfebD7S9AIziPBRYkAkDww | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/zfebD7S9AIziPBRYkAkDww?ver=15.1.0 | true | false | true | 2020-10-06T11:02:36Z |


### f5-asm-policy-xml-profiles-update
***
Updates an XML profile in a policy


#### Base Command

`f5-asm-policy-xml-profiles-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| xml_id | The ID of the XML profile. The ID or display name must be filled. Default is "None". | Optional | 
| xml_name | The display name of the XML profile. The ID or display name must be filled. | Required | 
| description | Optional description for the profile. | Optional | 
| check_signatures | Whether the profile should check for attack signatures. | Optional | 
| check_metachar_elements | Whether to check for metachar elements. | Optional | 
| check_metachar_attributes | Whether to check for metachar attributes. | Optional | 
| enable_wss | Whether to enable web services securities. | Optional | 
| inspect_soap | Whether to inspect SOAP attachments. | Optional | 
| follow_links | Whether to follow schema links. | Optional | 
| use_xml_response | Whether to use the XML response page. | Optional | 
| allow_cdata | Whether to allow CDATA. | Optional | 
| allow_dtds | Whether to allow DTDs. | Optional | 
| allow_external_ref | Whether to allow external references. | Optional | 
| allow_processing_instructions | Whether to allow processing instructions. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.XMLProfile.id | String | The ID of the XML profile. | 
| f5.XMLProfile.name | String | The display name of the XML profile. | 
| f5.XMLProfile.description | String | A description of the XML profile. | 
| f5.XMLProfile.isDefault | Boolean | Whether the XML profile is the default profile. | 
| f5.XMLProfile.attackSignaturesCheck | Boolean | Whether the XML profile should check for attack signatures. | 
| f5.XMLProfile.followSchemaLinks | Boolean | Whether the profile should follow schema links. | 
| f5.XMLProfile.metacharElementCheck | Boolean | Whether the XML profile should check for metachar elements. | 
| f5.XMLProfile.metacharAttributeCheck | Boolean | Whether the profile should check for metachar attributes. | 
| f5.XMLProfile.isReferenced | Boolean | Whether the XML profile is referenced. | 
| f5.XMLProfile.enableWSS | Boolean | Whether the web service security should be enabled. | 
| f5.XMLProfile.hasValidationFiles | Boolean | Whether the XML profile has validation files. | 
| f5.XMLProfile.selfLink | String | The self link to the specific profile. | 
| f5.XMLProfile.lastUpdate | String | The time the last update was made to the profile. | 


#### Command Example
```!f5-asm-policy-xml-profiles-update  policy_md5=kpD2qFaUlGAbw8RhN5IFQA xml_name=test_xml_profile```

#### Context Example
```
{
    "f5": {
        "XMLProfile": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": true,
            "hasValidationFiles": null,
            "id": "zfebD7S9AIziPBRYkAkDww",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:36Z",
            "mandatory": null,
            "metacharElementCheck": false,
            "method": null,
            "name": "test_xml_profile",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/zfebD7S9AIziPBRYkAkDww?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for updating XML profile:
>|name|id|selfLink|attackSignaturesCheck|metacharElementCheck|followSchemaLinks|lastUpdateMicros|
>|---|---|---|---|---|---|---|
>| test_xml_profile | zfebD7S9AIziPBRYkAkDww | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/zfebD7S9AIziPBRYkAkDww?ver=15.1.0 | true | false | true | 2020-10-06T11:02:36Z |


### f5-asm-policy-xml-profiles-delete
***
Deletes an existing XML profile from a policy


#### Base Command

`f5-asm-policy-xml-profiles-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| xml_id | The ID of the XML profile. The ID or display name must be filled. Default is "None". | Optional | 
| xml_name | The display name of the XML profile. The ID or display name must be filled. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.XMLProfile.id | String | The ID of the XML profile. | 
| f5.XMLProfile.name | String | The display name of the XML profile. | 
| f5.XMLProfile.description | String | A description of the XML profile. | 
| f5.XMLProfile.isDefault | Boolean | Whether the XML profile is the default profile. | 
| f5.XMLProfile.attackSignaturesCheck | Boolean | Whether the XML profile should check for attack signatures. | 
| f5.XMLProfile.followSchemaLinks | Boolean | Whether the profile should follow schema links. | 
| f5.XMLProfile.metacharElementCheck | Boolean | Whether the XML profile should check for metachar elements. | 
| f5.XMLProfile.metacharAttributeCheck | Boolean | Whether the profile should check for metachar attributes. | 
| f5.XMLProfile.isReferenced | Boolean | Whether the XML profile is referenced. | 
| f5.XMLProfile.enableWSS | Boolean | Whether the web service security should be enabled. | 
| f5.XMLProfile.hasValidationFiles | Boolean | Whether the XML profile has validation files. | 
| f5.XMLProfile.selfLink | String | The self link to the specific profile. | 
| f5.XMLProfile.lastUpdate | String | The time the last update was made to the profile. | 


#### Command Example
```!f5-asm-policy-xml-profiles-delete policy_md5=kpD2qFaUlGAbw8RhN5IFQA xml_name=test_xml_profile```

#### Context Example
```
{
    "f5": {
        "XMLProfile": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": true,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": "",
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": true,
            "hasValidationFiles": null,
            "id": "zfebD7S9AIziPBRYkAkDww",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:36Z",
            "mandatory": null,
            "metacharElementCheck": false,
            "method": null,
            "name": "test_xml_profile",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/zfebD7S9AIziPBRYkAkDww?ver=15.1.0",
            "serverTechnologyName": null,
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting XML profile:
>|name|id|selfLink|attackSignaturesCheck|metacharElementCheck|followSchemaLinks|lastUpdateMicros|
>|---|---|---|---|---|---|---|
>| test_xml_profile | zfebD7S9AIziPBRYkAkDww | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/xml-profiles/zfebD7S9AIziPBRYkAkDww?ver=15.1.0 | true | false | true | 2020-10-06T11:02:36Z |


### f5-asm-policy-server-technologies-list
***
Lists all server technologies in a policy.


#### Base Command

`f5-asm-policy-server-technologies-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.ServerTechnology.id | String | The ID of the server technology. | 
| f5.ServerTechnology.selfLink | String | The self link to the specific server technology. | 
| f5.ServerTechnology.serverTechnologyName | String | The display name of the server technology. | 
| f5.ServerTechnology.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-server-technologies-list policy_md5=7FWxqE2a-3bbpJimP4amtA```

#### Context Example
```
{
    "f5": {
        "ServerTechnology": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "9v-Sp7QveE-BE2EimSjVew",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-16T11:01:18Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/9v-Sp7QveE-BE2EimSjVew?ver=15.1.0",
                "serverTechnologyName": "Microsoft Windows",
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "5cSssMYANPqrl6gRBMfvMQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-16T11:01:18Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/5cSssMYANPqrl6gRBMfvMQ?ver=15.1.0",
                "serverTechnologyName": "ASP.NET",
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "89yK8lM69m7Z8zoJ1Y-c_g",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-16T11:01:18Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/89yK8lM69m7Z8zoJ1Y-c_g?ver=15.1.0",
                "serverTechnologyName": "Front Page Server Extensions (FPSE)",
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "attackSignaturesCheck": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "dataType": null,
                "description": null,
                "enableWSS": null,
                "enforcementType": null,
                "followSchemaLinks": null,
                "hasValidationFiles": null,
                "id": "V3PzMrvIWi_9ZM0m0y-92w",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "isCookie": null,
                "isHeader": null,
                "lastUpdateMicros": "2020-08-16T11:01:18Z",
                "mandatory": null,
                "mandatoryBody": null,
                "metacharElementCheck": null,
                "method": null,
                "name": null,
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/V3PzMrvIWi_9ZM0m0y-92w?ver=15.1.0",
                "serverTechnologyName": "IIS",
                "trustedByPolicyBuilder": null,
                "type": null,
                "valueType": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 list of all server technologies:
>|serverTechnologyName|id|selfLink|lastUpdateMicros|
>|---|---|---|---|
>| Microsoft Windows | 9v-Sp7QveE-BE2EimSjVew | https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/9v-Sp7QveE-BE2EimSjVew?ver=15.1.0 | 2020-08-16T11:01:18Z |
>| ASP.NET | 5cSssMYANPqrl6gRBMfvMQ | https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/5cSssMYANPqrl6gRBMfvMQ?ver=15.1.0 | 2020-08-16T11:01:18Z |
>| Front Page Server Extensions (FPSE) | 89yK8lM69m7Z8zoJ1Y-c_g | https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/89yK8lM69m7Z8zoJ1Y-c_g?ver=15.1.0 | 2020-08-16T11:01:18Z |
>| IIS | V3PzMrvIWi_9ZM0m0y-92w | https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/V3PzMrvIWi_9ZM0m0y-92w?ver=15.1.0 | 2020-08-16T11:01:18Z |


### f5-asm-policy-server-technologies-add
***
Add a server technology to a policy


#### Base Command

`f5-asm-policy-server-technologies-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| technology_id | The ID of the server technology. The ID or display name must be filled. Default is "None". | Optional | 
| technology_name | The display name of the server technology. The ID or display name must be filled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.ServerTechnology.id | String | The ID of the server technology. | 
| f5.ServerTechnology.selfLink | String | The self link to the specific server technology. | 
| f5.ServerTechnology.serverTechnologyName | String | The display name of the server technology. | 
| f5.ServerTechnology.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-server-technologies-add policy_md5=7FWxqE2a-3bbpJimP4amtA technology_name=ASP```

#### Context Example
```
{
    "f5": {
        "ServerTechnology": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "741BtgAqkVgEMykKfRxIIg",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:46Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": null,
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/741BtgAqkVgEMykKfRxIIg?ver=15.1.0",
            "serverTechnologyName": "ASP",
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding server technology:
>|serverTechnologyName|id|serverTechnologyName|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| ASP | 741BtgAqkVgEMykKfRxIIg | ASP | https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/741BtgAqkVgEMykKfRxIIg?ver=15.1.0 | 2020-10-06T11:02:46Z |


### f5-asm-policy-server-technologies-delete
***
Deletes a server technology from a policy.


#### Base Command

`f5-asm-policy-server-technologies-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_md5 | The MD5 hash of the policy. You can get the policy md5 using the f5-asm-get-policy-md5 command. | Required | 
| technology_id | The ID of the server technology. The ID or display name must be filled. Default is "None". | Optional | 
| technology_name | The display name of the server technology. The ID or display name must be filled. Default is "None". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.ServerTechnology.id | String | The ID of the server technology. | 
| f5.ServerTechnology.selfLink | String | The self link to the specific server technology. | 
| f5.ServerTechnology.serverTechnologyName | String | The display name of the server technology. | 
| f5.ServerTechnology.lastUpdateMicros | String | The datetime of the last update represented in micro seconds since 1970-01-01 00:00:00 GMT \(Unix epoch\). For example, 1519382317000000 is Friday, 23 February 2018 10:38:37. | 


#### Command Example
```!f5-asm-policy-server-technologies-delete policy_md5=7FWxqE2a-3bbpJimP4amtA technology_name=ASP```

#### Context Example
```
{
    "f5": {
        "ServerTechnology": {
            "actAsMethod": null,
            "allowed": null,
            "attackSignaturesCheck": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "dataType": null,
            "description": null,
            "enableWSS": null,
            "enforcementType": null,
            "followSchemaLinks": null,
            "hasValidationFiles": null,
            "id": "741BtgAqkVgEMykKfRxIIg",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "isCookie": null,
            "isHeader": null,
            "lastUpdateMicros": "2020-10-06T11:02:46Z",
            "mandatory": null,
            "metacharElementCheck": null,
            "method": null,
            "name": null,
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": null,
            "postDataLength": null,
            "protocol": null,
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/741BtgAqkVgEMykKfRxIIg?ver=15.1.0",
            "serverTechnologyName": "ASP",
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null,
            "valueType": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing server technology:
>|serverTechnologyName|id|serverTechnologyName|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| ASP | 741BtgAqkVgEMykKfRxIIg | ASP | https://localhost/mgmt/tm/asm/policies/7FWxqE2a-3bbpJimP4amtA/server-technologies/741BtgAqkVgEMykKfRxIIg?ver=15.1.0 | 2020-10-06T11:02:46Z |


### f5-asm-get-policy-md5
***
Gets the MD5 hash of a policy that can be accessed in the API.


#### Base Command

`f5-asm-get-policy-md5`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The display name of the policy to get a hash for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Policy.md5 | String | The MD5 hash of the policy. | 


#### Command Example
```!f5-asm-get-policy-md5 policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "Policy": {
            "md5": "kpD2qFaUlGAbw8RhN5IFQA"
        }
    }
}
```

#### Human Readable Output

>### Results
>|md5|
>|---|
>| kpD2qFaUlGAbw8RhN5IFQA |

