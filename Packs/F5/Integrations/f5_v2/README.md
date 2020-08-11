## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### f5-asm-policy-list
***
list all policies


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
| f5.ListPolicy.name | String | name of the policy | 
| f5.ListPolicy.active | Boolean | Indicates if the policy is active | 
| f5.ListPolicy.creator-name | String | Indicates the user that created the policy | 
| f5.ListPolicy.created-time | String | Indicated the time that the policy was created | 
| f5.ListPolicy.enforcement-mode | Boolean | Indicates if the policy is in enforcement mode | 
| f5.ListPolicy.type | String | policy type | 


#### Command Example
```!f5-asm-policy-list```

#### Context Example
```
{
    "f5": {
        "ListPolicies": [
            {
                "active": true,
                "createdTime": "2020-08-05T20:58:47Z",
                "creatorName": "admin",
                "enforcementMode": "blocking",
                "id": "kpD2qFaUlGAbw8RhN5IFQA",
                "name": "Test_Policy",
                "type": "security"
            },
            {
                "active": false,
                "createdTime": "2020-07-27T14:06:28Z",
                "creatorName": "admin",
                "enforcementMode": "blocking",
                "id": "eTzNEnVBWVG87KIljElZIw",
                "name": "Lior-test",
                "type": "security"
            },
            {
                "active": false,
                "createdTime": "2020-07-02T21:11:06Z",
                "creatorName": "tsconfd",
                "enforcementMode": "blocking",
                "id": "JOUWVIcEjvePSjYEMXhL3A",
                "name": "Test_Policy2",
                "type": "security"
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for listing policies:
>|name|id|type|active|
>|---|---|---|---|
>| Test_Policy | kpD2qFaUlGAbw8RhN5IFQA | security | true |
>| Lior-test | eTzNEnVBWVG87KIljElZIw | security | false |
>| Test_Policy2 | JOUWVIcEjvePSjYEMXhL3A | security | false |


### f5-asm-policy-apply
***
Applying a policy in application security manager


#### Base Command

`f5-asm-policy-apply`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_reference_link | link to the policy the user wish to apply | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.ApplyPolicy.id | String | Policy ID | 
| f5.ApplyPolicy.kind | String | Policy kind | 
| f5.ApplyPolicy.policy-reference | String | policy reference link | 
| f5.ApplyPolicy.status | String | policy status | 
| f5.ApplyPolicy.start-time | String | Policy start time | 


#### Command Example
```!f5-asm-policy-apply policy_reference_link="https://192.168.30.76/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0"```

#### Context Example
```
{
    "f5": {
        "ApplyPolicy": {
            "id": "rDsg_fntTK5jNKP_Slshjg",
            "kind": "tm:asm:tasks:apply-policy:apply-policy-taskstate",
            "policyReference": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0",
            "startTime": "2020-08-11T16:02:16Z",
            "status": "NEW"
        }
    }
}
```

#### Human Readable Output

>### f5 data for applying policy:
>|id|kind|policyReference|startTime|status|
>|---|---|---|---|---|
>| rDsg_fntTK5jNKP_Slshjg | tm:asm:tasks:apply-policy:apply-policy-taskstate | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0 | 2020-08-11T16:02:16Z | NEW |


### f5-asm-policy-export-file
***
export policy file


#### Base Command

`f5-asm-policy-export-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filename | name of the file to export to | Required | 
| policy_reference_link | link to policy user wishes to export | Required | 
| minimal | Indicates whether to export only custom settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.ExportPolicy.kind | String | policy kind | 
| f5.ExportPolicy.format | String | policy format | 
| f5.ExportPolicy.filename | String | filename of the file exported | 
| f5.ExportPolicy.policy-reference | String | policy reference link | 
| f5.ExportPolicy.id | String | policy id | 
| f5.ExportPolicy.start-time | String | policy start time | 
| f5.ExportPolicy.status | String | policy status | 


#### Command Example
```!f5-asm-policy-export-file filename="exported_file.xml" policy_reference_link="https://192.168.30.76/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0"```

#### Context Example
```
{
    "f5": {
        "ExportPolicy": {
            "filename": "exported_file.xml",
            "format": "xml",
            "id": "erI1Tg-bEX3woKuUTFzFwA",
            "kind": "tm:asm:tasks:export-policy:export-policy-taskstate",
            "startTime": "2020-08-11T16:02:17Z",
            "status": "NEW"
        }
    },
    "policy-reference": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0"
}
```

#### Human Readable Output

>### f5 data for exporting policy:
>|filename|format|id|kind|startTime|status|
>|---|---|---|---|---|---|
>| exported_file.xml | xml | erI1Tg-bEX3woKuUTFzFwA | tm:asm:tasks:export-policy:export-policy-taskstate | 2020-08-11T16:02:17Z | NEW |


### f5-asm-policy-methods-list
***
Lists the HTTP methods that are enforced in the security policy.


#### Base Command

`f5-asm-policy-methods-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The policy name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.PolicyMethods.name | String | Method name | 
| f5.PolicyMethods.act-as-method | String | The functionality of the method | 
| f5.PolicyMethods.id | String | Method ID | 
| f5.PolicyMethods.self-link | String | Self link | 
| f5.PolicyMethods.kind | String | Endpoint kind | 
| f5.PolicyMethods.last-updated | String | Last update time | 


#### Command Example
```!f5-asm-policy-methods-list policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "PolicyMethods": [
            {
                "actAsMethod": "POST",
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": null,
                "enforcementType": null,
                "id": "QB1BzVdfL5WfSHrpP_2MOQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-11T12:32:56Z",
                "mandatoryBody": null,
                "method": null,
                "name": "test_get_2",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/QB1BzVdfL5WfSHrpP_2MOQ?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": null
            },
            {
                "actAsMethod": "GET",
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": null,
                "enforcementType": null,
                "id": "fY-VmdD8p450Aqd86HMKtQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-11T12:30:44Z",
                "mandatoryBody": null,
                "method": null,
                "name": "test_get",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/fY-VmdD8p450Aqd86HMKtQ?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": null
            },
            {
                "actAsMethod": "GET",
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": null,
                "enforcementType": null,
                "id": "9l8WogEiTHYEa8UzGruaBg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T21:07:26Z",
                "mandatoryBody": null,
                "method": null,
                "name": "getty",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/9l8WogEiTHYEa8UzGruaBg?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": null
            },
            {
                "actAsMethod": "GET",
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": null,
                "enforcementType": null,
                "id": "4V4hb8HGOfeHsSMezfob-A",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T20:58:48Z",
                "mandatoryBody": null,
                "method": null,
                "name": "HEAD",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/4V4hb8HGOfeHsSMezfob-A?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": null
            },
            {
                "actAsMethod": "POST",
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": null,
                "enforcementType": null,
                "id": "oCQ57CKdi-DnSwwWAjkjEA",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T20:58:48Z",
                "mandatoryBody": null,
                "method": null,
                "name": "POST",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/oCQ57CKdi-DnSwwWAjkjEA?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": null
            },
            {
                "actAsMethod": "GET",
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": null,
                "enforcementType": null,
                "id": "dSgDWpPuac7bHb3bLwv8yA",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T20:58:48Z",
                "mandatoryBody": null,
                "method": null,
                "name": "GET",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/dSgDWpPuac7bHb3bLwv8yA?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for PolicyMethods:
>|name|id|actAsMethod|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| test_get_2 | QB1BzVdfL5WfSHrpP_2MOQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/QB1BzVdfL5WfSHrpP_2MOQ?ver=15.1.0 | 2020-08-11T12:32:56Z |
>| test_get | fY-VmdD8p450Aqd86HMKtQ | GET | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/fY-VmdD8p450Aqd86HMKtQ?ver=15.1.0 | 2020-08-11T12:30:44Z |
>| getty | 9l8WogEiTHYEa8UzGruaBg | GET | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/9l8WogEiTHYEa8UzGruaBg?ver=15.1.0 | 2020-08-05T21:07:26Z |
>| HEAD | 4V4hb8HGOfeHsSMezfob-A | GET | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/4V4hb8HGOfeHsSMezfob-A?ver=15.1.0 | 2020-08-05T20:58:48Z |
>| POST | oCQ57CKdi-DnSwwWAjkjEA | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/oCQ57CKdi-DnSwwWAjkjEA?ver=15.1.0 | 2020-08-05T20:58:48Z |
>| GET | dSgDWpPuac7bHb3bLwv8yA | GET | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/dSgDWpPuac7bHb3bLwv8yA?ver=15.1.0 | 2020-08-05T20:58:48Z |


### f5-asm-policy-file-type-list
***
Lists the file types that are allowed or disallowed in the security policy.


#### Base Command

`f5-asm-policy-file-type-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The policy name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.FileType.name | String | Method name | 
| f5.FileType.id | String | Method ID | 
| f5.FileType.self-link | String | Self link | 
| f5.FileType.kind | String | Endpoint kind | 
| f5.FileType.last-updated | String | Last update time | 
| f5.FileType.query-string-length | String | Length of the query | 
| f5.FileType.check-request-length | String | Request length | 
| f5.FileType.allowed | Boolean | Indicates if the file type allowed | 


#### Command Example
```!f5-asm-policy-file-type-list policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "FileType": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": null,
                "enforcementType": null,
                "id": "3-1bwXe4erMXxYTgZWatxg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T21:05:35Z",
                "mandatoryBody": null,
                "method": null,
                "name": "py",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "queryStringLength": 100,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/3-1bwXe4erMXxYTgZWatxg?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "explicit"
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": null,
                "enforcementType": null,
                "id": "mOgzedRVODecKsTkfDvoHQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T21:05:11Z",
                "mandatoryBody": null,
                "method": null,
                "name": "exe",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "queryStringLength": 100,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/mOgzedRVODecKsTkfDvoHQ?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "explicit"
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": true,
                "blockRequests": null,
                "checkRequestLength": true,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": null,
                "enforcementType": null,
                "id": "M4na42GvebBMnI5wV_YMxg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T20:58:49Z",
                "mandatoryBody": null,
                "method": null,
                "name": "*",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": true,
                "protocol": null,
                "queryStringLength": 1000,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/M4na42GvebBMnI5wV_YMxg?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "wildcard"
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for FileType:
>|name|id|type|selfLink|queryStringLength|checkRequestLength|performStaging|lastUpdateMicros|allowed|
>|---|---|---|---|---|---|---|---|---|
>| py | 3-1bwXe4erMXxYTgZWatxg | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/3-1bwXe4erMXxYTgZWatxg?ver=15.1.0 | 100 | true | false | 2020-08-05T21:05:35Z | true |
>| exe | mOgzedRVODecKsTkfDvoHQ | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/mOgzedRVODecKsTkfDvoHQ?ver=15.1.0 | 100 | true | false | 2020-08-05T21:05:11Z | true |
>| * | M4na42GvebBMnI5wV_YMxg | wildcard | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/M4na42GvebBMnI5wV_YMxg?ver=15.1.0 | 1000 | true | true | 2020-08-05T20:58:49Z | true |


### f5-asm-policy-methods-add
***
add new allowed method


#### Base Command

`f5-asm-policy-methods-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The policy name you want to add method to | Required | 
| new_method_name | Display name of the new method. | Required | 
| act_as_method | Functionality of the new method. default is GET. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.PolicyMethods.name | String | The name of the new method | 
| f5.PolicyMethods.id | String | ID of the new method | 
| f5.PolicyMethods.act-as-method | String | Functionality of the new method. | 
| f5.PolicyMethods.self-link | String | self link | 
| f5.PolicyMethods.kind | String | kind | 


#### Command Example
```!f5-asm-policy-methods-add policy_name=Test_Policy new_method_name="Posty" act_as_method="POST"```

#### Context Example
```
{
    "f5": {
        "PolicyMethods": {
            "actAsMethod": "POST",
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "description": null,
            "enforcementType": null,
            "id": "cwMuAdnzCUXmGBTc552zvQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:23Z",
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
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all PolicyMethods:
>|name|id|actAsMethod|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| Posty | cwMuAdnzCUXmGBTc552zvQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0 | 2020-08-11T16:02:23Z |


### f5-asm-policy-methods-update
***
update a policy method


#### Base Command

`f5-asm-policy-methods-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The policy name. | Required | 
| method_name | Display name of the method. | Required | 
| act_as_method | Functionality of the new method. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.PolicyMethods.name | String | The name of the new method | 
| f5.PolicyMethods.id | String | ID of the new method | 
| f5.PolicyMethods.act-as-method | String | Functionality of the new method. | 
| f5.PolicyMethods.self-link | String | self link | 
| f5.PolicyMethods.kind | String | kind | 


#### Command Example
```!f5-asm-policy-methods-update policy_name=Test_Policy method_name="Posty" act_as_method="POST"```

#### Context Example
```
{
    "f5": {
        "PolicyMethods": {
            "actAsMethod": "POST",
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "description": null,
            "enforcementType": null,
            "id": "cwMuAdnzCUXmGBTc552zvQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:23Z",
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
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all PolicyMethods:
>|name|id|actAsMethod|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| Posty | cwMuAdnzCUXmGBTc552zvQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0 | 2020-08-11T16:02:23Z |


### f5-asm-policy-methods-delete
***
Delete a method from a certain policy


#### Base Command

`f5-asm-policy-methods-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The policy name. | Required | 
| method_name | Display name of the method. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.PolicyMethods.name | String | The name of the new method | 
| f5.PolicyMethods.id | String | ID of the new method | 
| f5.PolicyMethods.act-as-method | String | Functionality of the new method. | 
| f5.PolicyMethods.self-link | String | self link | 
| f5.PolicyMethods.kind | String | kind | 


#### Command Example
```!f5-asm-policy-methods-delete policy_name=Test_Policy method_name="Posty"```

#### Context Example
```
{
    "f5": {
        "PolicyMethods": {
            "actAsMethod": "POST",
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "description": null,
            "enforcementType": null,
            "id": "cwMuAdnzCUXmGBTc552zvQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:23Z",
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
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all PolicyMethods:
>|name|id|actAsMethod|selfLink|lastUpdateMicros|
>|---|---|---|---|---|
>| Posty | cwMuAdnzCUXmGBTc552zvQ | POST | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0 | 2020-08-11T16:02:23Z |


### f5-asm-policy-file-type-add
***
add new file type


#### Base Command

`f5-asm-policy-file-type-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the policy to add the file type to | Required | 
| new_file_type | The new file type to add. | Required | 
| query_string_length | Query string length. | Optional | 
| check_post_data_length | indicates if the user wishes check the length of data in post method. default is True. | Optional | 
| response_check | Indicates if the user wishes to check the response. | Optional | 
| check_request_length | Indicates if the user wishes to check the request length. | Optional | 
| post_data_length | post data length. | Optional | 
| perform_staging | Indicates if the user wishes the new file type to be at staging. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.FileType.name | String | Method name | 
| f5.FileType.id | String | Method ID | 
| f5.FileType.query-string-length | Number | Indicates the query string length | 
| f5.FileType.self-link | String | self link | 
| f5.FileType.last-updated | String | Last update time | 
| f5.FileType.response-check | Boolean | Indicates if user wished to check response | 
| f5.FileType.check-request-length | String | Request length | 
| f5.FileType.allowed | Boolean | Indicates if the file type allowed | 
| f5.FileType.check-url-length | Boolean | Indicates if user wishes to check url length | 
| f5.FileType.post-data-length | Number | Length od the post data | 
| f5.FileType.url-length | Number | Indicates the url length | 
| f5.FileType.perform-staging | Boolean | Indicates if staging was performed. | 


#### Command Example
```!f5-asm-policy-file-type-add policy_name=Test_Policy new_file_type="txt"```

#### Context Example
```
{
    "f5": {
        "FileType": {
            "actAsMethod": null,
            "allowed": true,
            "blockRequests": null,
            "checkRequestLength": true,
            "checkUrlLength": true,
            "clickjackingProtection": null,
            "createdBy": null,
            "description": null,
            "enforcementType": null,
            "id": "x4JPPU1fey8i0DR1jB6UVA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:28Z",
            "method": null,
            "name": "txt",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": 100,
            "protocol": null,
            "queryStringLength": 100,
            "responseCheck": true,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0",
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": 100
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all FileType:
>|name|id|type|selfLink|queryStringLength|checkRequestLength|responseCheck|urlLength|checkUrlLength|postDataLength|performStaging|allowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| txt | x4JPPU1fey8i0DR1jB6UVA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0 | 100 | true | true | 100 | true | 100 | false | true | 2020-08-11T16:02:28Z |


### f5-asm-policy-file-type-update
***
update policy file type


#### Base Command

`f5-asm-policy-file-type-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the policy to add the file type to | Required | 
| file_type_name | The fie type user wishes to update | Required | 
| query_string_length | Query string length. | Optional | 
| check_post_data_length | indicates if the user wishes check the length of data in post method. default is True. | Optional | 
| response_check | Indicates if the user wishes to check the response. | Optional | 
| check_request_length | Indicates if the user wishes to check the request length. | Optional | 
| post_data_length | post data length. | Optional | 
| perform_staging | Indicates if the user wishes the new file type to be at staging. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.FileType.name | String | Method name | 
| f5.FileType.id | String | Method ID | 
| f5.FileType.query-string-length | Number | Indicates the query string length | 
| f5.FileType.self-link | String | self link | 
| f5.FileType.last-updated | String | Last update time | 
| f5.FileType.response-check | Boolean | Indicates if user wished to check response | 
| f5.FileType.check-request-length | String | Request length | 
| f5.FileType.allowed | Boolean | Indicates if the file type allowed | 
| f5.FileType.check-url-length | Boolean | Indicates if user wishes to check url length | 
| f5.FileType.post-data-length | Number | Length od the post data | 
| f5.FileType.url-length | Number | Indicates the url length | 
| f5.FileType.perform-staging | Boolean | Indicates if staging was performed. | 


#### Command Example
```!f5-asm-policy-file-type-update policy_name=Test_Policy file_type_name="txt"```

#### Context Example
```
{
    "f5": {
        "FileType": {
            "actAsMethod": null,
            "allowed": true,
            "blockRequests": null,
            "checkRequestLength": true,
            "checkUrlLength": true,
            "clickjackingProtection": null,
            "createdBy": null,
            "description": null,
            "enforcementType": null,
            "id": "x4JPPU1fey8i0DR1jB6UVA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:28Z",
            "method": null,
            "name": "txt",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": 100,
            "protocol": null,
            "queryStringLength": 100,
            "responseCheck": true,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0",
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": 100
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all FileType:
>|name|id|type|selfLink|queryStringLength|checkRequestLength|responseCheck|urlLength|checkUrlLength|postDataLength|performStaging|allowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| txt | x4JPPU1fey8i0DR1jB6UVA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0 | 100 | true | true | 100 | true | 100 | false | true | 2020-08-11T16:02:28Z |


### f5-asm-policy-file-type-delete
***
Delete policy file type


#### Base Command

`f5-asm-policy-file-type-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The policy name. | Required | 
| file_type_name | The new file type to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.policy-delete.name | String | Name of the policy that was deleted | 
| f5.policy-delete.id | String | ID of the policy that was deleted | 
| f5.policy-delete.self-link | String | Self link of the policy that was deleted | 


#### Command Example
```!f5-asm-policy-file-type-delete policy_name=Test_Policy file_type_name="txt"```

#### Context Example
```
{
    "f5": {
        "FileType": {
            "actAsMethod": null,
            "allowed": true,
            "blockRequests": null,
            "checkRequestLength": true,
            "checkUrlLength": true,
            "clickjackingProtection": null,
            "createdBy": null,
            "description": null,
            "enforcementType": null,
            "id": "x4JPPU1fey8i0DR1jB6UVA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:28Z",
            "method": null,
            "name": "txt",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": 100,
            "protocol": null,
            "queryStringLength": 100,
            "responseCheck": true,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0",
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": 100
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all FileType:
>|name|id|type|selfLink|queryStringLength|checkRequestLength|responseCheck|urlLength|checkUrlLength|postDataLength|performStaging|allowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| txt | x4JPPU1fey8i0DR1jB6UVA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0 | 100 | true | true | 100 | true | 100 | false | true | 2020-08-11T16:02:28Z |


### f5-asm-policy-delete
***
Delete policy


#### Base Command

`f5-asm-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The policy name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.DeletePolicy.name | String | Name of the deleted policy. | 
| f5.DeletePolicy.id | String | ID of the deleted policy. | 
| f5.DeletePolicy.self-link | String | Self link of the deleted policy. | 


#### Command Example
```!f5-asm-policy-delete policy_name=Test_Policyy```

#### Context Example
```
{
    "f5": {
        "delete-policy": {
            "id": "63EXMG4Y3tJ--Fo0GjuAkw",
            "name": "Test_Policyy",
            "self-link": "https://localhost/mgmt/tm/asm/policies/63EXMG4Y3tJ--Fo0GjuAkw?ver=15.1.0"
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleting policy:
>|name|id|self-link|
>|---|---|---|
>| Test_Policyy | 63EXMG4Y3tJ--Fo0GjuAkw | https://localhost/mgmt/tm/asm/policies/63EXMG4Y3tJ--Fo0GjuAkw?ver=15.1.0 |



### f5-asm-policy-hostnames-list
***
List policy hostnames


#### Base Command

`f5-asm-policy-hostnames-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy you wish to get hostnames for | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Hostname.name | String | Policy hostname | 
| f5.Hostname.id | String | Policy ID | 
| f5.Hostname.created-by | String | Interface used to create the hostname | 
| f5.Hostname.self-link | String | URI of specific hostname | 
| f5.Hostname.include-subdomains | Boolean | Whether or not to include subdomains | 
| f5.Hostname.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-policy-hostnames-list policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "Hostname": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "description": null,
                "enforcementType": null,
                "id": "tM6UhfuSaPYYRnUS6-k2vg",
                "ignoreAnomalies": null,
                "includeSubdomains": true,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-11T13:24:10Z",
                "mandatoryBody": null,
                "method": null,
                "name": "qmasters.co.il",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/tM6UhfuSaPYYRnUS6-k2vg?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "description": null,
                "enforcementType": null,
                "id": "_3pBVxU6gHchLIdX_Tm4vQ",
                "ignoreAnomalies": null,
                "includeSubdomains": false,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T21:09:06Z",
                "mandatoryBody": null,
                "method": null,
                "name": "cnn",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/_3pBVxU6gHchLIdX_Tm4vQ?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "description": null,
                "enforcementType": null,
                "id": "HVkg9LRLJ6gCvXfE8FNvWg",
                "ignoreAnomalies": null,
                "includeSubdomains": false,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T21:08:39Z",
                "mandatoryBody": null,
                "method": null,
                "name": "google.com",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/HVkg9LRLJ6gCvXfE8FNvWg?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for Hostname:
>|name|id|selfLink|includeSubdomains|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|
>| qmasters.co.il | tM6UhfuSaPYYRnUS6-k2vg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/tM6UhfuSaPYYRnUS6-k2vg?ver=15.1.0 | true | GUI | 2020-08-11T13:24:10Z |
>| cnn | _3pBVxU6gHchLIdX_Tm4vQ | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/_3pBVxU6gHchLIdX_Tm4vQ?ver=15.1.0 | false | GUI | 2020-08-05T21:09:06Z |
>| google.com | HVkg9LRLJ6gCvXfE8FNvWg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/HVkg9LRLJ6gCvXfE8FNvWg?ver=15.1.0 | false | GUI | 2020-08-05T21:08:39Z |


### f5-asm-policy-hostnames-add
***
Add a new hostname to a policy


#### Base Command

`f5-asm-policy-hostnames-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to add a hostname to | Required | 
| name | Host name to add | Required | 
| include_subdomains | Whether or not to include subdomains | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Hostname.name | String | Policy hostname | 
| f5.Hostname.id | String | Policy ID | 
| f5.Hostname.created-by | String | Interface used to create the hostname | 
| f5.Hostname.self-link | String | URI of specific hostname | 
| f5.Hostname.include-subdomains | Boolean | Whether or not to include subdomains | 
| f5.Hostname.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-policy-hostnames-add policy_name=Test_Policy name=qmasters.co```

#### Context Example
```
{
    "f5": {
        "Hostname": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "description": null,
            "enforcementType": null,
            "id": "dsblcoDkMkFb_A_H6BS6eA",
            "ignoreAnomalies": null,
            "includeSubdomains": false,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:37Z",
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
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all Hostname:
>|name|id|selfLink|includeSubdomains|includeSubdomains|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|
>| qmasters.co | dsblcoDkMkFb_A_H6BS6eA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0 | false | false | GUI | 2020-08-11T16:02:37Z |


### f5-asm-policy-hostnames-update
***
Update an existing policy hostname


#### Base Command

`f5-asm-policy-hostnames-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to update hostname in. | Required | 
| name | Host name to update | Required | 
| include_subdomains | Whether or not to include subdomains | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Hostname.name | String | Policy hostname | 
| f5.Hostname.id | String | Policy ID | 
| f5.Hostname.created-by | String | Interface used to create the hostname | 
| f5.Hostname.self-link | String | URI of specific hostname | 
| f5.Hostname.include-subdomains | Boolean | Whether or not to include subdomains | 
| f5.Hostname.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-policy-hostnames-update policy_name=Test_Policy name=qmasters.co include_subdomains=true```

#### Context Example
```
{
    "f5": {
        "Hostname": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "description": null,
            "enforcementType": null,
            "id": "dsblcoDkMkFb_A_H6BS6eA",
            "ignoreAnomalies": null,
            "includeSubdomains": true,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:38Z",
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
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all Hostname:
>|name|id|selfLink|includeSubdomains|includeSubdomains|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|
>| qmasters.co | dsblcoDkMkFb_A_H6BS6eA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0 | true | true | GUI | 2020-08-11T16:02:38Z |


### f5-asm-policy-hostnames-delete
***
Delete a hostname from a policy


#### Base Command

`f5-asm-policy-hostnames-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of policy to delete from | Required | 
| name | Name of hostname to delete | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Hostname.name | String | Policy hostname | 
| f5.Hostname.id | String | Policy ID | 
| f5.Hostname.created-by | String | Interface used to create the hostname | 
| f5.Hostname.self-link | String | URI of specific hostname | 
| f5.Hostname.include-subdomains | Boolean | Whether or not to include subdomains | 
| f5.Hostname.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-policy-hostnames-delete policy_name=Test_Policy name=qmasters.co```

#### Context Example
```
{
    "f5": {
        "Hostname": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "description": null,
            "enforcementType": null,
            "id": "dsblcoDkMkFb_A_H6BS6eA",
            "ignoreAnomalies": null,
            "includeSubdomains": true,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:38Z",
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
            "trustedByPolicyBuilder": null,
            "type": null,
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all Hostname:
>|name|id|selfLink|includeSubdomains|includeSubdomains|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|
>| qmasters.co | dsblcoDkMkFb_A_H6BS6eA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0 | true | true | GUI | 2020-08-11T16:02:38Z |


### f5-asm-policy-cookies-list
***
List all cookies of a given policy


#### Base Command

`f5-asm-policy-cookies-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to retreive from | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Cookies.name | String | Cookies name | 
| f5.Cookies.id | String | Cookie ID | 
| f5.Cookies.self-link | String | Cookie self link | 
| f5.Cookies.enforcement-type | String | Enforcement type | 
| f5.Cookies.perform-staging | Boolean | Indicates if perform staging | 
| f5.Cookies.kind | String | Object kind | 
| f5.Cookies.is-base-64 | Boolean | Indicated if base 64 | 
| f5.Cookies.created-by | String | Indicates which user created this cookie. | 


#### Command Example
```!f5-asm-policy-cookies-list policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "Cookies": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "description": null,
                "enforcementType": "allow",
                "id": "w3iYXWKemaToYhPbDNXnDQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "lastUpdateMicros": "2020-08-11T15:21:54Z",
                "mandatoryBody": null,
                "method": null,
                "name": "chocolate",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": true,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/w3iYXWKemaToYhPbDNXnDQ?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "explicit"
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "description": null,
                "enforcementType": "allow",
                "id": "E1g7FVU2CYuY30F-Rp_MUw",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "lastUpdateMicros": "2020-08-05T21:04:51Z",
                "mandatoryBody": null,
                "method": null,
                "name": "yummy",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/E1g7FVU2CYuY30F-Rp_MUw?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "explicit"
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "description": null,
                "enforcementType": "allow",
                "id": "HeC08NE594GztN6H7bTecA",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "lastUpdateMicros": "2020-08-05T21:04:43Z",
                "mandatoryBody": null,
                "method": null,
                "name": "yum",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": false,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/HeC08NE594GztN6H7bTecA?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "explicit"
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "description": null,
                "enforcementType": "allow",
                "id": "M4na42GvebBMnI5wV_YMxg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": null,
                "isBase64": false,
                "lastUpdateMicros": "2020-08-05T20:58:49Z",
                "mandatoryBody": null,
                "method": null,
                "name": "*",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": true,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/M4na42GvebBMnI5wV_YMxg?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "wildcard"
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for Cookies:
>|name|id|type|selfLink|enforcementType|isBase64|performStaging|createdBy|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|
>| chocolate | w3iYXWKemaToYhPbDNXnDQ | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/w3iYXWKemaToYhPbDNXnDQ?ver=15.1.0 | allow | false | true | GUI | 2020-08-11T15:21:54Z |
>| yummy | E1g7FVU2CYuY30F-Rp_MUw | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/E1g7FVU2CYuY30F-Rp_MUw?ver=15.1.0 | allow | false | false | GUI | 2020-08-05T21:04:51Z |
>| yum | HeC08NE594GztN6H7bTecA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/HeC08NE594GztN6H7bTecA?ver=15.1.0 | allow | false | false | GUI | 2020-08-05T21:04:43Z |
>| * | M4na42GvebBMnI5wV_YMxg | wildcard | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/M4na42GvebBMnI5wV_YMxg?ver=15.1.0 | allow | false | true | GUI | 2020-08-05T20:58:49Z |


### f5-asm-policy-blocking-settings-list
***
Retreive a BS list from a selected policy.


#### Base Command

`f5-asm-policy-blocking-settings-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The policy name. | Required | 
| endpoint | Sub-path of the BS element | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.BlockingSettings.description | String | Element description | 
| f5.BlockingSettings.learn | Boolean | Is the element learning | 
| f5.BlockingSettings.id | String | Element ID | 
| f5.BlockingSettings.kind | String | Kind of element | 
| f5.BlockingSettings.enabled | Boolean | Is the element enabled | 
| f5.BlockingSettings.self-link | String | Link to the element | 
| f5.BlockingSettings.reference | String | Reference to the element | 
| f5.BlockingSettings.last-update | String | Time when the resource was last updated | 
| f5.BlockingSettings.section-reference | String | Section reference to the element | 
| f5.BlockingSettings.alarm | Boolean | Should the element alarm | 
| f5.BlockingSettings.block | Boolean | Should the element block | 


#### Command Example
```!f5-asm-policy-blocking-settings-list policy_name=Test_Policy endpoint=evasions```

#### Context Example
```
{
    "f5": {
        "BlockingSettings": [
            {
                "alarm": null,
                "block": null,
                "description": "Bad unescape",
                "enabled": false,
                "id": "9--k-GSum4jUNSf0sU91Dw",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "last-update": "2020-08-11T14:43:18Z",
                "learn": false,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0",
                "section-reference": null,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "Apache whitespace",
                "enabled": false,
                "id": "Ahu8fuILcRNNU-ICBr1v6w",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "last-update": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0",
                "section-reference": null,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "Bare byte decoding",
                "enabled": false,
                "id": "EKfN2XD-E1z097tVwOO1nw",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "last-update": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0",
                "section-reference": null,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "IIS Unicode codepoints",
                "enabled": false,
                "id": "dtxhHW66r8ZswIeccbXbXA",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "last-update": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0",
                "section-reference": null,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "IIS backslashes",
                "enabled": false,
                "id": "6l0vHEYIIy4H06o9mY5RNQ",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "last-update": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0",
                "section-reference": null,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "%u decoding",
                "enabled": false,
                "id": "Y2TT8PSVtqudz407XG4LAQ",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "last-update": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0",
                "section-reference": null,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "Multiple decoding",
                "enabled": false,
                "id": "x02XsB6uJX5Eqp1brel7rw",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "last-update": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0",
                "section-reference": null,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0"
            },
            {
                "alarm": null,
                "block": null,
                "description": "Directory traversals",
                "enabled": false,
                "id": "qH_2eaLz5x2RgaZ7dUISLA",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "last-update": "2020-08-05T20:58:49Z",
                "learn": true,
                "reference": "https://localhost/mgmt/tm/asm/sub-violations/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0",
                "section-reference": null,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### Evasions for selected policy
>|id|description|enabled|learn|kind|reference|self-link|last-update|
>|---|---|---|---|---|---|---|---|
>| 9--k-GSum4jUNSf0sU91Dw | Bad unescape | false | false | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0 | 2020-08-11T14:43:18Z |
>| Ahu8fuILcRNNU-ICBr1v6w | Apache whitespace | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| EKfN2XD-E1z097tVwOO1nw | Bare byte decoding | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| dtxhHW66r8ZswIeccbXbXA | IIS Unicode codepoints | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| 6l0vHEYIIy4H06o9mY5RNQ | IIS backslashes | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| Y2TT8PSVtqudz407XG4LAQ | %u decoding | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| x02XsB6uJX5Eqp1brel7rw | Multiple decoding | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| qH_2eaLz5x2RgaZ7dUISLA | Directory traversals | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0 | 2020-08-05T20:58:49Z |


### f5-asm-policy-blocking-settings-update
***
Update a BS element


#### Base Command

`f5-asm-policy-blocking-settings-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy the element exists in | Required | 
| endpoint | The subpath the element resides in | Required | 
| description | Description (or name) of the element. | Required | 
| learn | Should the element learn | Optional | 
| alarm | Should the element alarm | Optional | 
| block | Should the element block | Optional | 
| enabled | Should the element be enabled | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.BlockingSettings.description | String | Element description | 
| f5.BlockingSettings.learn | Boolean | Is the element learning | 
| f5.BlockingSettings.id | String | Element ID | 
| f5.BlockingSettings.kind | String | Kind of element | 
| f5.BlockingSettings.enabled | Boolean | Is the element enabled | 
| f5.BlockingSettings.self-link | String | Link to the element | 
| f5.BlockingSettings.reference | String | Reference to the element | 
| f5.BlockingSettings.last-update | String | Time when the resource was last updated | 
| f5.BlockingSettings.section-reference | String | Section reference to the element | 
| f5.BlockingSettings.alarm | Boolean | Should the element alarm | 
| f5.BlockingSettings.block | Boolean | Should the element block | 


#### Command Example
```!f5-asm-policy-blocking-settings-update policy_name=Test_Policy endpoint=evasions description="Bad unescape"  ```

#### Context Example
```
{
    "f5": {
        "BlockingSettings": {
            "alarm": null,
            "block": null,
            "description": "Bad unescape",
            "enabled": false,
            "id": "9--k-GSum4jUNSf0sU91Dw",
            "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
            "last-update": "2020-08-11T14:43:18Z",
            "learn": false,
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0"
        }
    }
}
```

#### Human Readable Output

>### Modified blocking-settings/evasions
>|id|description|enabled|learn|kind|self-link|last-update|
>|---|---|---|---|---|---|---|
>| 9--k-GSum4jUNSf0sU91Dw | Bad unescape | false | false | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0 | 2020-08-11T14:43:18Z |


### f5-asm-policy-urls-list
***
List all policy URLs


#### Base Command

`f5-asm-policy-urls-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to retreive URLs from | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Url.id | String | URL ID | 
| f5.Url.name | String | URL name | 
| f5.Url.description | String | Description of the URL | 
| f5.Url.protocol | String | Protocol the URL uses. | 
| f5.Url.type | String | Is the URL explicit or wildcard | 
| f5.Url.method | String | Allowed method \(or all\) | 
| f5.Url.is-allowed | Boolean | Is the URL allowed. | 
| f5.Url.clickjacking-protection | Boolean | Is clickjacking protection enabled in the URL. | 
| f5.Url.perform-staging | Boolean | Is the URL in staging. | 
| f5.Url.mandatory-body | Boolean | Is a body mandatory | 
| f5.Url.self-link | String | Path the the URL in the api. | 
| f5.Url.last-update | String | Time of last update committed to the URL | 


#### Command Example
```!f5-asm-policy-urls-list policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "Url": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": "GUI",
                "description": null,
                "enforcementType": null,
                "id": "6ER7SOq208zow5rraOzwyQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": false,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-11T14:00:44Z",
                "mandatoryBody": true,
                "method": "*",
                "name": "/http",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": null,
                "protocol": "http",
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/6ER7SOq208zow5rraOzwyQ?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "explicit"
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": false,
                "createdBy": "GUI",
                "description": "",
                "enforcementType": null,
                "id": "faiefv884qtHRU3Qva2AbQ",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": true,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T20:58:51Z",
                "mandatoryBody": false,
                "method": "*",
                "name": "*",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": true,
                "protocol": "http",
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/faiefv884qtHRU3Qva2AbQ?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "wildcard"
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": null,
                "checkRequestLength": null,
                "clickjackingProtection": false,
                "createdBy": "GUI",
                "description": "",
                "enforcementType": null,
                "id": "N_a3D1S7OKDehYEPb-mgCg",
                "ignoreAnomalies": null,
                "includeSubdomains": null,
                "ipAddress": null,
                "ipMask": null,
                "isAllowed": true,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T20:58:51Z",
                "mandatoryBody": false,
                "method": "*",
                "name": "*",
                "neverLearnRequests": null,
                "neverLogRequests": null,
                "performStaging": true,
                "protocol": "https",
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/N_a3D1S7OKDehYEPb-mgCg?ver=15.1.0",
                "trustedByPolicyBuilder": null,
                "type": "wildcard"
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for Url:
>|name|id|type|protocol|method|selfLink|mandatoryBody|clickjackingProtection|performStaging|createdBy|lastUpdateMicros|isAllowed|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| /http | 6ER7SOq208zow5rraOzwyQ | explicit | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/6ER7SOq208zow5rraOzwyQ?ver=15.1.0 | true |  |  | GUI | 2020-08-11T14:00:44Z | false |
>| * | faiefv884qtHRU3Qva2AbQ | wildcard | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/faiefv884qtHRU3Qva2AbQ?ver=15.1.0 | false | false | true | GUI | 2020-08-05T20:58:51Z | true |
>| * | N_a3D1S7OKDehYEPb-mgCg | wildcard | https | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/N_a3D1S7OKDehYEPb-mgCg?ver=15.1.0 | false | false | true | GUI | 2020-08-05T20:58:51Z | true |


### f5-asm-policy-cookies-add
***
Add new cookie to a specific policy


#### Base Command

`f5-asm-policy-cookies-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to add to | Required | 
| new_cookie_name | The new cookie name to add. | Required | 
| perform_staging | Indicates if the user wishes the new file type to be at staging. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Cookies.name | String | Cookie name | 
| f5.Cookies.id | String | Cookie ID | 
| f5.Cookies.self-link | String | Cookie self link | 
| f5.Cookies.enforcement-type | String | Enforcement type | 
| f5.Cookies.perform-staging | Boolean | Indicates if the user wishes to perform staging | 
| f5.Cookies.type | String | Type | 
| f5.Cookies.is-base-64 | Boolean | Indicates if base 64 | 
| f5.Cookies.created-by | String | Indicates the user created the cookie | 


#### Command Example
```!f5-asm-policy-cookies-add policy_name=Test_Policy new_cookie_name=new_cookie```

#### Context Example
```
{
    "f5": {
        "Cookies": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "description": null,
            "enforcementType": "allow",
            "id": "7t_U2dbYEAQp89Wp0m_QoA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": false,
            "lastUpdateMicros": "2020-08-11T16:02:32Z",
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
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all Cookies:
>|name|id|type|selfLink|enforcementType|isBase64|createdBy|performStaging|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|
>| new_cookie | 7t_U2dbYEAQp89Wp0m_QoA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0 | allow | false | GUI | false | 2020-08-11T16:02:32Z |


### f5-asm-policy-urls-add
***
Add a new URL to a policy


#### Base Command

`f5-asm-policy-urls-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The policy name | Required | 
| protocol | Communication protocol (HTTP/S) | Required | 
| name | Name of the new URL | Required | 
| description | Optional description for the URL | Optional | 
| url_type | Type of URL (explicit or wildcard) | Optional | 
| is_allowed | Whether or not the URL is allowed | Optional | 
| method | What method to use in the URL | Optional | 
| clickjacking_protection | Is clickjacking protection enabled in the URL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Url.id | String | URL ID | 
| f5.Url.name | String | URL name | 
| f5.Url.description | String | Description of the URL | 
| f5.Url.protocol | String | Protocol the URL uses. | 
| f5.Url.type | String | Is the URL explicit or wildcard | 
| f5.Url.method | String | Allowed method \(or all\) | 
| f5.Url.is-allowed | Boolean | Is the URL allowed. | 
| f5.Url.clickjacking-protection | Boolean | Is clickjacking protection enabled in the URL. | 
| f5.Url.perform-staging | Boolean | Is the URL in staging. | 
| f5.Url.mandatory-body | Boolean | Is a body mandatory | 
| f5.Url.selfLink | String | Path the the URL in the api. | 
| f5.Url.last-update | String | Time of last update committed to the URL | 


#### Command Example
```!f5-asm-policy-urls-add policy_name=Test_Policy protocol=http name=http_example```

#### Context Example
```
{
    "f5": {
        "Url": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": false,
            "createdBy": "GUI",
            "description": "",
            "enforcementType": null,
            "id": "q_O5IGzUqSmFYZhlkA1CpQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": true,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:44Z",
            "method": "*",
            "name": "/http_example",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": "http",
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/q_O5IGzUqSmFYZhlkA1CpQ?ver=15.1.0",
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all Url:
>|name|id|type|protocol|method|selfLink|clickjackingProtection|createdBy|performStaging|isAllowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|
>| /http_example | q_O5IGzUqSmFYZhlkA1CpQ | explicit | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/q_O5IGzUqSmFYZhlkA1CpQ?ver=15.1.0 | false | GUI | false | true | 2020-08-11T16:02:44Z |


### f5-asm-policy-urls-update
***
Update an existing policy URL


#### Base Command

`f5-asm-policy-urls-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy the URL is in | Required | 
| name | Name of the URL | Required | 
| perform_staging | Whether or not to stage the URL | Optional | 
| description | Optional new description for the URL | Optional | 
| mandatory_body | Whether or not to have a mandatory body | Optional | 
| url_isreferrer | Whether or not the URL is a referrer. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Url.id | String | URL ID | 
| f5.Url.name | String | URL name | 
| f5.Url.description | String | Description of the URL | 
| f5.Url.protocol | String | Protocol the URL uses. | 
| f5.Url.type | String | Is the URL explicit or wildcard | 
| f5.Url.method | String | Allowed method \(or all\) | 
| f5.Url.is-allowed | Boolean | Is the URL allowed. | 
| f5.Url.clickjacking-protection | Boolean | Is clickjacking protection enabled in the URL. | 
| f5.Url.perform-staging | Boolean | Is the URL in staging. | 
| f5.Url.mandatory-body | Boolean | Is a body mandatory | 
| f5.Url.selfLink | String | Path the the URL in the api. | 
| f5.Url.last-update | String | Time of last update committed to the URL | 


#### Command Example
```!f5-asm-policy-urls-update policy_name=Test_Policy name="/http_example"```

#### Context Example
```
{
    "f5": {
        "Url": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": false,
            "createdBy": "GUI",
            "description": "",
            "enforcementType": null,
            "id": "q_O5IGzUqSmFYZhlkA1CpQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": true,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:44Z",
            "method": "*",
            "name": "/http_example",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": "http",
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/q_O5IGzUqSmFYZhlkA1CpQ?ver=15.1.0",
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all Url:
>|name|id|type|protocol|method|selfLink|clickjackingProtection|createdBy|performStaging|isAllowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|
>| /http_example | q_O5IGzUqSmFYZhlkA1CpQ | explicit | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/q_O5IGzUqSmFYZhlkA1CpQ?ver=15.1.0 | false | GUI | false | true | 2020-08-11T16:02:44Z |


### f5-asm-policy-urls-delete
***
Delete a URL from a policy


#### Base Command

`f5-asm-policy-urls-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy the URL is in. | Required | 
| name | Name of the URL | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Url.id | String | URL ID | 
| f5.Url.name | String | URL name | 
| f5.Url.description | String | Description of the URL | 
| f5.Url.protocol | String | Protocol the URL uses. | 
| f5.Url.type | String | Is the URL explicit or wildcard | 
| f5.Url.method | String | Allowed method \(or all\) | 
| f5.Url.is-allowed | Boolean | Is the URL allowed. | 
| f5.Url.clickjacking-protection | Boolean | Is clickjacking protection enabled in the URL. | 
| f5.Url.perform-staging | Boolean | Is the URL in staging. | 
| f5.Url.mandatory-body | Boolean | Is a body mandatory | 
| f5.Url.self-link | String | Path the the URL in the api. | 
| f5.Url.last-update | String | Time of last update committed to the URL | 


#### Command Example
```!f5-asm-policy-urls-delete policy_name=Test_Policy name="/http_example"```

#### Context Example
```
{
    "f5": {
        "Url": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": false,
            "createdBy": "GUI",
            "description": "",
            "enforcementType": null,
            "id": "q_O5IGzUqSmFYZhlkA1CpQ",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": true,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:44Z",
            "method": "*",
            "name": "/http_example",
            "neverLearnRequests": null,
            "neverLogRequests": null,
            "performStaging": false,
            "postDataLength": null,
            "protocol": "http",
            "queryStringLength": null,
            "responseCheck": null,
            "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/q_O5IGzUqSmFYZhlkA1CpQ?ver=15.1.0",
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all Url:
>|name|id|type|protocol|method|selfLink|clickjackingProtection|createdBy|performStaging|isAllowed|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|---|
>| /http_example | q_O5IGzUqSmFYZhlkA1CpQ | explicit | http | * | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/q_O5IGzUqSmFYZhlkA1CpQ?ver=15.1.0 | false | GUI | false | true | 2020-08-11T16:02:44Z |


### f5-asm-policy-cookies-update
***
Update a cookie object


#### Base Command

`f5-asm-policy-cookies-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy the cookie is in. | Required | 
| cookie_name | Name of the cookie | Required | 
| perform_staging | Indicates if the user wishes the new file type to be at staging. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Cookies.name | String | Cookie name | 
| f5.Cookies.id | String | Cookie ID | 
| f5.Cookies.self-link | String | Cookie self link | 
| f5.Cookies.enforcement-type | String | Enforcement type | 
| f5.Cookies.perform-staging | Boolean | Indicates if the user wishes to perform staging | 
| f5.Cookies.type | String | Type | 
| f5.Cookies.is-base-64 | Boolean | Indicates if base 64 | 
| f5.Cookies.created-by | String | Indicates the user created the cookie | 


#### Command Example
```!f5-asm-policy-cookies-update policy_name=Test_Policy cookie_name=new_cookie```

#### Context Example
```
{
    "f5": {
        "Cookies": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "description": null,
            "enforcementType": "allow",
            "id": "7t_U2dbYEAQp89Wp0m_QoA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": false,
            "lastUpdateMicros": "2020-08-11T16:02:32Z",
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
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all Cookies:
>|name|id|type|selfLink|enforcementType|isBase64|createdBy|performStaging|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|
>| new_cookie | 7t_U2dbYEAQp89Wp0m_QoA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0 | allow | false | GUI | false | 2020-08-11T16:02:32Z |


### f5-asm-policy-cookies-delete
***
Delete cookie


#### Base Command

`f5-asm-policy-cookies-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy | Required | 
| cookie_name | Name of the cookie to delete | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.Cookies.name | String | Cookie name | 
| f5.Cookies.id | String | Cookie ID | 
| f5.Cookies.self-link | String | Cookie self link | 
| f5.Cookies.enforcement-type | String | Enforcement type | 
| f5.Cookies.perform-staging | Boolean | Indicates if the user wishes to perform staging | 
| f5.Cookies.type | String | Type | 
| f5.Cookies.is-base-64 | Boolean | Indicates if base 64 | 
| f5.Cookies.created-by | String | Indicates the user created the cookie | 


#### Command Example
```!f5-asm-policy-cookies-delete policy_name=Test_Policy cookie_name=new_cookie```

#### Context Example
```
{
    "f5": {
        "Cookies": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": null,
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": "GUI",
            "description": null,
            "enforcementType": "allow",
            "id": "7t_U2dbYEAQp89Wp0m_QoA",
            "ignoreAnomalies": null,
            "includeSubdomains": null,
            "ipAddress": null,
            "ipMask": null,
            "isAllowed": null,
            "isBase64": false,
            "lastUpdateMicros": "2020-08-11T16:02:32Z",
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
            "trustedByPolicyBuilder": null,
            "type": "explicit",
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all Cookies:
>|name|id|type|selfLink|enforcementType|isBase64|createdBy|performStaging|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|
>| new_cookie | 7t_U2dbYEAQp89Wp0m_QoA | explicit | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0 | allow | false | GUI | false | 2020-08-11T16:02:32Z |


### f5-asm-policy-whitelist-ips-list
***
List all whitelisted IPs for a policy


#### Base Command

`f5-asm-policy-whitelist-ips-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to get IPs for | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.WhitelistIP.id | String | ID of the whitelisted IP | 
| f5.WhitelistIP.ip-address | String | The whitelisted IP address | 
| f5.WhitelistIP.ip-mask | String | Subnet mask of the whitelisted IP address | 
| f5.WhitelistIP.description | String | Description for the whitelisted IP | 
| f5.WhitelistIP.block-requests | String | How or if the IP blocks requests | 
| f5.WhitelistIP.ignore-anomalies | Boolean | Whether or not to ignore anomalies | 
| f5.WhitelistIP.never-log-requests | Boolean | Whether or not to never log requests | 
| f5.WhitelistIP.never-learn-requests | Boolean | Whether or not to never learn requests | 
| f5.WhitelistIP.trusted-by-policy-builder | Boolean | Whether or not the IP is trusted by the builder. | 
| f5.WhitelistIP.self-link | String | Link to the whitelisted IP. | 
| f5.WhitelistIP.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-policy-whitelist-ips-list policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "WhitelistIP": [
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": "",
                "enforcementType": null,
                "id": "4CuqTmGkqfI01diFbc2PJQ",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "100.100.100.100",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T21:13:09Z",
                "mandatoryBody": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/4CuqTmGkqfI01diFbc2PJQ?ver=15.1.0",
                "trustedByPolicyBuilder": false,
                "type": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": "",
                "enforcementType": null,
                "id": "lbpOAL2E2f2C7qp7kiV3OA",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "20.20.20.20",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T21:13:38Z",
                "mandatoryBody": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/lbpOAL2E2f2C7qp7kiV3OA?ver=15.1.0",
                "trustedByPolicyBuilder": false,
                "type": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": "",
                "enforcementType": null,
                "id": "Uey6PzyJhbb6Qm-w0RD__Q",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "30.30.30.30",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-05T21:13:48Z",
                "mandatoryBody": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/Uey6PzyJhbb6Qm-w0RD__Q?ver=15.1.0",
                "trustedByPolicyBuilder": false,
                "type": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": "",
                "enforcementType": null,
                "id": "9lSC2hzsLvpsEgSTEpi4yw",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "11.22.33.44",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-09T15:15:56Z",
                "mandatoryBody": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/9lSC2hzsLvpsEgSTEpi4yw?ver=15.1.0",
                "trustedByPolicyBuilder": false,
                "type": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": "",
                "enforcementType": null,
                "id": "F2ZRy81hCYIAnYolA0fqzg",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "1.2.3.44",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-11T14:32:19Z",
                "mandatoryBody": null,
                "method": null,
                "name": null,
                "neverLearnRequests": false,
                "neverLogRequests": true,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/F2ZRy81hCYIAnYolA0fqzg?ver=15.1.0",
                "trustedByPolicyBuilder": false,
                "type": null
            },
            {
                "actAsMethod": null,
                "active": null,
                "allowed": null,
                "blockRequests": "policy-default",
                "checkRequestLength": null,
                "clickjackingProtection": null,
                "createdBy": null,
                "description": "",
                "enforcementType": null,
                "id": "6fatQ08fMtHzcywc4gQDJA",
                "ignoreAnomalies": false,
                "includeSubdomains": null,
                "ipAddress": "1.2.3.144",
                "ipMask": "255.255.255.255",
                "isAllowed": null,
                "isBase64": null,
                "lastUpdateMicros": "2020-08-11T14:31:24Z",
                "mandatoryBody": null,
                "method": null,
                "name": null,
                "neverLearnRequests": true,
                "neverLogRequests": false,
                "performStaging": null,
                "protocol": null,
                "queryStringLength": null,
                "selfLink": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/6fatQ08fMtHzcywc4gQDJA?ver=15.1.0",
                "trustedByPolicyBuilder": true,
                "type": null
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for WhitelistIP:
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
Add a new whitelisted IP to a policy.


#### Base Command

`f5-asm-policy-whitelist-ips-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to add the IP to. | Required | 
| ip_address | The new IP address | Required | 
| ip_mask | Subnet mask for the new IP | Optional | 
| trusted_by_builder | Whether or not the IP is trusted by the policy builder. | Optional | 
| ignore_brute_detection | Whether or not to ignore detections of brute force. | Optional | 
| description | Optional description for the new IP. | Optional | 
| block_requests | Method of blocking requests. | Optional | 
| ignore_learning | Whether or not to ignore learning suggestions. | Optional | 
| never_log | Whether or not to never log from the IP. | Optional | 
| ignore_intelligence | Whether or not to ignore intelligence gathered on the IP. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.WhitelistIP.id | String | ID of the whitelisted IP | 
| f5.WhitelistIP.ip-address | String | The whitelisted IP address | 
| f5.WhitelistIP.ip-mask | String | Subnet mask of the whitelisted IP address | 
| f5.WhitelistIP.description | String | Description for the whitelisted IP | 
| f5.WhitelistIP.block-requests | String | How or if the IP blocks requests | 
| f5.WhitelistIP.ignore-anomalies | Boolean | Whether or not to ignore anomalies | 
| f5.WhitelistIP.never-log-requests | Boolean | Whether or not to never log requests | 
| f5.WhitelistIP.never-learn-requests | Boolean | Whether or not to never learn requests | 
| f5.WhitelistIP.trusted-by-policy-builder | Boolean | Whether or not the IP is trusted by the builder. | 
| f5.WhitelistIP.self-link | String | Link to the whitelisted IP. | 
| f5.WhitelistIP.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-policy-whitelist-ips-add policy_name=Test_Policy ip_address=1.2.3.4```

#### Context Example
```
{
    "f5": {
        "WhitelistIP": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": "policy-default",
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "description": "",
            "enforcementType": null,
            "id": "pwbUREF-1u-BDw9MrdisOA",
            "ignoreAnomalies": false,
            "includeSubdomains": null,
            "ipAddress": "1.2.3.4",
            "ipMask": "255.255.255.255",
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:49Z",
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
            "trustedByPolicyBuilder": false,
            "type": null,
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all WhitelistIP:
>|id|selfLink|ipAddress|ipMask|blockRequests|ignoreAnomalies|neverLogRequests|neverLearnRequests|trustedByPolicyBuilder|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| pwbUREF-1u-BDw9MrdisOA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0 | 1.2.3.4 | 255.255.255.255 | policy-default | false | false | false | false | 2020-08-11T16:02:49Z |


### f5-asm-policy-whitelist-ips-update
***
Update an existing whitelisted IP.


#### Base Command

`f5-asm-policy-whitelist-ips-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to update the IP in. | Required | 
| ip_address | IP address | Required | 
| trusted_by_builder | Whether or not the IP is trusted by the policy builder. | Optional | 
| ignore_brute_detection | Whether or not to ignore detections of brute force. | Optional | 
| description | Optional description for the new IP. | Optional | 
| block_requests | Method of blocking requests. | Optional | 
| ignore_learning | Whether or not to ignore learning suggestions. | Optional | 
| never_log | Whether or not to never log from the IP. | Optional | 
| ignore_intelligence | Whether or not to ignore intelligence gathered on the IP. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.WhitelistIP.id | String | ID of the whitelisted IP | 
| f5.WhitelistIP.ip-address | String | The whitelisted IP address | 
| f5.WhitelistIP.ip-mask | String | Subnet mask of the whitelisted IP address | 
| f5.WhitelistIP.description | String | Description for the whitelisted IP | 
| f5.WhitelistIP.block-requests | String | How or if the IP blocks requests | 
| f5.WhitelistIP.ignore-anomalies | Boolean | Whether or not to ignore anomalies | 
| f5.WhitelistIP.never-log-requests | Boolean | Whether or not to never log requests | 
| f5.WhitelistIP.never-learn-requests | Boolean | Whether or not to never learn requests | 
| f5.WhitelistIP.trusted-by-policy-builder | Boolean | Whether or not the IP is trusted by the builder. | 
| f5.WhitelistIP.self-link | String | Link to the whitelisted IP. | 
| f5.WhitelistIP.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-policy-whitelist-ips-update policy_name=Test_Policy ip_address=1.2.3.4```

#### Context Example
```
{
    "f5": {
        "WhitelistIP": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": "policy-default",
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "description": "",
            "enforcementType": null,
            "id": "pwbUREF-1u-BDw9MrdisOA",
            "ignoreAnomalies": false,
            "includeSubdomains": null,
            "ipAddress": "1.2.3.4",
            "ipMask": "255.255.255.255",
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:49Z",
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
            "trustedByPolicyBuilder": false,
            "type": null,
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all WhitelistIP:
>|id|selfLink|ipAddress|ipMask|blockRequests|ignoreAnomalies|neverLogRequests|neverLearnRequests|trustedByPolicyBuilder|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| pwbUREF-1u-BDw9MrdisOA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0 | 1.2.3.4 | 255.255.255.255 | policy-default | false | false | false | false | 2020-08-11T16:02:49Z |


### f5-asm-policy-whitelist-ips-delete
***
Delete an existing whitelisted IP from a policy.


#### Base Command

`f5-asm-policy-whitelist-ips-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to delete the IP from. | Required | 
| ip_address | IP address. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.WhitelistIP.id | String | ID of the whitelisted IP | 
| f5.WhitelistIP.ip-address | String | The whitelisted IP address | 
| f5.WhitelistIP.ip-mask | String | Subnet mask of the whitelisted IP address | 
| f5.WhitelistIP.description | String | Description for the whitelisted IP | 
| f5.WhitelistIP.block-requests | String | How or if the IP blocks requests | 
| f5.WhitelistIP.ignore-anomalies | Boolean | Whether or not to ignore anomalies | 
| f5.WhitelistIP.never-log-requests | Boolean | Whether or not to never log requests | 
| f5.WhitelistIP.never-learn-requests | Boolean | Whether or not to never learn requests | 
| f5.WhitelistIP.trusted-by-policy-builder | Boolean | Whether or not the IP is trusted by the builder. | 
| f5.WhitelistIP.self-link | String | Link to the whitelisted IP. | 
| f5.WhitelistIP.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-policy-whitelist-ips-delete policy_name=Test_Policy ip_address=1.2.3.4```

#### Context Example
```
{
    "f5": {
        "WhitelistIP": {
            "actAsMethod": null,
            "allowed": null,
            "blockRequests": "policy-default",
            "checkRequestLength": null,
            "checkUrlLength": null,
            "clickjackingProtection": null,
            "createdBy": null,
            "description": "",
            "enforcementType": null,
            "id": "pwbUREF-1u-BDw9MrdisOA",
            "ignoreAnomalies": false,
            "includeSubdomains": null,
            "ipAddress": "1.2.3.4",
            "ipMask": "255.255.255.255",
            "isAllowed": null,
            "isBase64": null,
            "lastUpdateMicros": "2020-08-11T16:02:49Z",
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
            "trustedByPolicyBuilder": false,
            "type": null,
            "urlLength": null
        }
    }
}
```

#### Human Readable Output

>### f5 data for listing all WhitelistIP:
>|id|selfLink|ipAddress|ipMask|blockRequests|ignoreAnomalies|neverLogRequests|neverLearnRequests|trustedByPolicyBuilder|lastUpdateMicros|
>|---|---|---|---|---|---|---|---|---|---|
>| pwbUREF-1u-BDw9MrdisOA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0 | 1.2.3.4 | 255.255.255.255 | policy-default | false | false | false | false | 2020-08-11T16:02:49Z |

