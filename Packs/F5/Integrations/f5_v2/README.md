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
        "list-policies": [
            {
                "active": false,
                "created-time": "2020-08-05T21:06:05Z",
                "creator-name": "admin",
                "enforcement-mode": "blocking",
                "id": "63EXMG4Y3tJ--Fo0GjuAkw",
                "name": "Test_Policyy",
                "type": "security"
            },
            {
                "active": false,
                "created-time": "2020-08-05T20:58:47Z",
                "creator-name": "admin",
                "enforcement-mode": "blocking",
                "id": "kpD2qFaUlGAbw8RhN5IFQA",
                "name": "Test_Policy",
                "type": "security"
            },
            {
                "active": false,
                "created-time": "2020-07-02T21:11:06Z",
                "creator-name": "tsconfd",
                "enforcement-mode": "blocking",
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
>|name|id|type|enforcement-mode|creator-name|active|created-time|
>|---|---|---|---|---|---|---|
>| Test_Policyy | 63EXMG4Y3tJ--Fo0GjuAkw | security | blocking | admin | false | 2020-08-05T21:06:05Z |
>| Test_Policy | kpD2qFaUlGAbw8RhN5IFQA | security | blocking | admin | false | 2020-08-05T20:58:47Z |
>| Test_Policy2 | JOUWVIcEjvePSjYEMXhL3A | security | blocking | tsconfd | false | 2020-07-02T21:11:06Z |


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
        "apply-policy": {
            "id": "gEOu_vi6USsrY2jMQbzH0g",
            "kind": "tm:asm:tasks:apply-policy:apply-policy-taskstate",
            "policy-reference": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0",
            "start-time": "2020-08-05T21:14:38Z",
            "status": "NEW"
        }
    }
}
```

#### Human Readable Output

>### f5 data for applying policy:
>|id|kind|policy-reference|start-time|status|
>|---|---|---|---|---|
>| gEOu_vi6USsrY2jMQbzH0g | tm:asm:tasks:apply-policy:apply-policy-taskstate | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0 | 2020-08-05T21:14:38Z | NEW |


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
        "export-policy": {
            "filename": "exported_file.xml",
            "format": "xml",
            "id": "itIfJ-Hp2yTSTv9hFp_Ycw",
            "kind": "tm:asm:tasks:export-policy:export-policy-taskstate",
            "start-time": "2020-08-05T21:14:39Z",
            "status": "NEW"
        }
    },
    "policy-reference": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA?ver=15.1.0"
}
```

#### Human Readable Output

>### f5 data for exporting policy:
>|filename|format|id|kind|start-time|status|
>|---|---|---|---|---|---|
>| exported_file.xml | xml | itIfJ-Hp2yTSTv9hFp_Ycw | tm:asm:tasks:export-policy:export-policy-taskstate | 2020-08-05T21:14:39Z | NEW |


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
        "policy-methods": [
            {
                "act-as-method": "GET",
                "id": "9l8WogEiTHYEa8UzGruaBg",
                "kind": "tm:asm:policies:methods:methodstate",
                "last-updated": "2020-08-05T21:07:26Z",
                "name": "getty",
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/9l8WogEiTHYEa8UzGruaBg?ver=15.1.0"
            },
            {
                "act-as-method": "GET",
                "id": "4V4hb8HGOfeHsSMezfob-A",
                "kind": "tm:asm:policies:methods:methodstate",
                "last-updated": "2020-08-05T20:58:48Z",
                "name": "HEAD",
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/4V4hb8HGOfeHsSMezfob-A?ver=15.1.0"
            },
            {
                "act-as-method": "POST",
                "id": "oCQ57CKdi-DnSwwWAjkjEA",
                "kind": "tm:asm:policies:methods:methodstate",
                "last-updated": "2020-08-05T20:58:48Z",
                "name": "POST",
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/oCQ57CKdi-DnSwwWAjkjEA?ver=15.1.0"
            },
            {
                "act-as-method": "GET",
                "id": "dSgDWpPuac7bHb3bLwv8yA",
                "kind": "tm:asm:policies:methods:methodstate",
                "last-updated": "2020-08-05T20:58:48Z",
                "name": "GET",
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/dSgDWpPuac7bHb3bLwv8yA?ver=15.1.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for listing all policy methods:
>|name|act-as-method|id|self-link|kind|last-updated|
>|---|---|---|---|---|---|
>| getty | GET | 9l8WogEiTHYEa8UzGruaBg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/9l8WogEiTHYEa8UzGruaBg?ver=15.1.0 | tm:asm:policies:methods:methodstate | 2020-08-05T21:07:26Z |
>| HEAD | GET | 4V4hb8HGOfeHsSMezfob-A | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/4V4hb8HGOfeHsSMezfob-A?ver=15.1.0 | tm:asm:policies:methods:methodstate | 2020-08-05T20:58:48Z |
>| POST | POST | oCQ57CKdi-DnSwwWAjkjEA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/oCQ57CKdi-DnSwwWAjkjEA?ver=15.1.0 | tm:asm:policies:methods:methodstate | 2020-08-05T20:58:48Z |
>| GET | GET | dSgDWpPuac7bHb3bLwv8yA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/dSgDWpPuac7bHb3bLwv8yA?ver=15.1.0 | tm:asm:policies:methods:methodstate | 2020-08-05T20:58:48Z |


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
        "file-types": [
            {
                "allowed": true,
                "check-request-length": true,
                "id": "3-1bwXe4erMXxYTgZWatxg",
                "kind": "tm:asm:policies:filetypes:filetypestate",
                "last-updated": "2020-08-05T21:05:35Z",
                "name": "py",
                "query-string-length": 100,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/3-1bwXe4erMXxYTgZWatxg?ver=15.1.0"
            },
            {
                "allowed": true,
                "check-request-length": true,
                "id": "mOgzedRVODecKsTkfDvoHQ",
                "kind": "tm:asm:policies:filetypes:filetypestate",
                "last-updated": "2020-08-05T21:05:11Z",
                "name": "exe",
                "query-string-length": 100,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/mOgzedRVODecKsTkfDvoHQ?ver=15.1.0"
            },
            {
                "allowed": true,
                "check-request-length": true,
                "id": "M4na42GvebBMnI5wV_YMxg",
                "kind": "tm:asm:policies:filetypes:filetypestate",
                "last-updated": "2020-08-05T20:58:49Z",
                "name": "*",
                "query-string-length": 1000,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/M4na42GvebBMnI5wV_YMxg?ver=15.1.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### Listing all f5 file type:
>|name|id|self-link|query-string-length|check-request-length|kind|allowed|last-updated|
>|---|---|---|---|---|---|---|---|
>| py | 3-1bwXe4erMXxYTgZWatxg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/3-1bwXe4erMXxYTgZWatxg?ver=15.1.0 | 100 | true | tm:asm:policies:filetypes:filetypestate | true | 2020-08-05T21:05:35Z |
>| exe | mOgzedRVODecKsTkfDvoHQ | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/mOgzedRVODecKsTkfDvoHQ?ver=15.1.0 | 100 | true | tm:asm:policies:filetypes:filetypestate | true | 2020-08-05T21:05:11Z |
>| * | M4na42GvebBMnI5wV_YMxg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/M4na42GvebBMnI5wV_YMxg?ver=15.1.0 | 1000 | true | tm:asm:policies:filetypes:filetypestate | true | 2020-08-05T20:58:49Z |


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
```!f5-asm-policy-methods-add ```

#### Human Readable Output



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
```!f5-asm-policy-methods-update ```

#### Human Readable Output



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
        "policy-methods": {
            "act-as-method": "POST",
            "id": "cwMuAdnzCUXmGBTc552zvQ",
            "kind": "tm:asm:policies:methods:methodstate",
            "name": "Posty",
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0"
        }
    }
}
```

#### Human Readable Output

>### f5 data for policy methods:
>|name|act-as-method|id|self-link|kind|
>|---|---|---|---|---|
>| Posty | POST | cwMuAdnzCUXmGBTc552zvQ | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/methods/cwMuAdnzCUXmGBTc552zvQ?ver=15.1.0 | tm:asm:policies:methods:methodstate |


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
        "file-type": {
            "allowed": true,
            "check-request-length": true,
            "check-url-length": true,
            "id": "x4JPPU1fey8i0DR1jB6UVA",
            "last-updated": "2020-08-05T21:15:28Z",
            "name": "txt",
            "perform-staging": false,
            "post-data-length": 100,
            "query-string-length": 100,
            "response-check": true,
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0",
            "url-length": 100
        }
    }
}
```

#### Human Readable Output

>### f5 data for file types:
>|name|id|self-link|query-string-length|check-request-length|response-check|check-url-length|url-length|post-data-length|perform-staging|allowed|last-updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| txt | x4JPPU1fey8i0DR1jB6UVA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0 | 100 | true | true | true | 100 | 100 | false | true | 2020-08-05T21:15:28Z |


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
        "file-type": {
            "allowed": true,
            "check-request-length": true,
            "check-url-length": true,
            "id": "x4JPPU1fey8i0DR1jB6UVA",
            "last-updated": "2020-08-05T21:15:28Z",
            "name": "txt",
            "perform-staging": false,
            "post-data-length": 100,
            "query-string-length": 100,
            "response-check": true,
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0",
            "url-length": 100
        }
    }
}
```

#### Human Readable Output

>### f5 data for file types:
>|name|id|self-link|query-string-length|check-request-length|response-check|check-url-length|url-length|post-data-length|perform-staging|allowed|last-updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| txt | x4JPPU1fey8i0DR1jB6UVA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0 | 100 | true | true | true | 100 | 100 | false | true | 2020-08-05T21:15:28Z |


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
        "file-type": {
            "allowed": true,
            "check-request-length": true,
            "check-url-length": true,
            "id": "x4JPPU1fey8i0DR1jB6UVA",
            "last-updated": "2020-08-05T21:15:28Z",
            "name": "txt",
            "perform-staging": false,
            "post-data-length": 100,
            "query-string-length": 100,
            "response-check": true,
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0",
            "url-length": 100
        }
    }
}
```

#### Human Readable Output

>### f5 data for file types:
>|name|id|self-link|query-string-length|check-request-length|response-check|check-url-length|url-length|post-data-length|perform-staging|allowed|last-updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| txt | x4JPPU1fey8i0DR1jB6UVA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/filetypes/x4JPPU1fey8i0DR1jB6UVA?ver=15.1.0 | 100 | true | true | true | 100 | 100 | false | true | 2020-08-05T21:15:28Z |


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
| f5.FileType.name | String | Name of the deleted policy. | 
| f5.FileType.id | String | ID of the deleted policy. | 
| f5.FileType.self-link | String | Self link of the deleted policy. | 


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


### f5-asm-resource-hostnames-list
***
List policy hostnames


#### Base Command

`f5-asm-resource-hostnames-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy you wish to get hostnames for | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.ResourceHostname.name | String | Policy hostname | 
| f5.ResourceHostname.id | String | Policy ID | 
| f5.ResourceHostname.created-by | String | Interface used to create the hostname | 
| f5.ResourceHostname.self-link | String | URI of specific hostname | 
| f5.ResourceHostname.include-subdomains | Boolean | Whether or not to include subdomains | 
| f5.ResourceHostname.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-resource-hostnames-list policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "resource-hostname": [
            {
                "created-by": "GUI",
                "id": "_3pBVxU6gHchLIdX_Tm4vQ",
                "include-subdomains": false,
                "last-update": "2020-08-05T21:09:06Z",
                "name": "cnn",
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/_3pBVxU6gHchLIdX_Tm4vQ?ver=15.1.0"
            },
            {
                "created-by": "GUI",
                "id": "HVkg9LRLJ6gCvXfE8FNvWg",
                "include-subdomains": false,
                "last-update": "2020-08-05T21:08:39Z",
                "name": "google.com",
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/HVkg9LRLJ6gCvXfE8FNvWg?ver=15.1.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 information about hosts
>|id|name|created-by|include-subdomains|self-link|last-update|
>|---|---|---|---|---|---|
>| _3pBVxU6gHchLIdX_Tm4vQ | cnn | GUI | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/_3pBVxU6gHchLIdX_Tm4vQ?ver=15.1.0 | 2020-08-05T21:09:06Z |
>| HVkg9LRLJ6gCvXfE8FNvWg | google.com | GUI | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/HVkg9LRLJ6gCvXfE8FNvWg?ver=15.1.0 | 2020-08-05T21:08:39Z |


### f5-asm-resource-hostnames-add
***
Add a new hostname to a policy


#### Base Command

`f5-asm-resource-hostnames-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to add a hostname to | Required | 
| name | Host name to add | Required | 
| include_subdomains | Whether or not to include subdomains | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.ResourceHostname.name | String | Policy hostname | 
| f5.ResourceHostname.id | String | Policy ID | 
| f5.ResourceHostname.created-by | String | Interface used to create the hostname | 
| f5.ResourceHostname.self-link | String | URI of specific hostname | 
| f5.ResourceHostname.include-subdomains | Boolean | Whether or not to include subdomains | 
| f5.ResourceHostname.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-resource-hostnames-add policy_name=Test_Policy name=qmasters.co```

#### Context Example
```
{
    "f5": {
        "resource-hostname": {
            "created-by": "GUI",
            "id": "dsblcoDkMkFb_A_H6BS6eA",
            "include-subdomains": false,
            "last-update": "2020-08-05T21:15:41Z",
            "name": "qmasters.co",
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0"
        }
    }
}
```

#### Human Readable Output

>### f5 information about hosts
>|id|name|created-by|include-subdomains|self-link|last-update|
>|---|---|---|---|---|---|
>| dsblcoDkMkFb_A_H6BS6eA | qmasters.co | GUI | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0 | 2020-08-05T21:15:41Z |


### f5-asm-resource-hostnames-update
***
Update an existing policy hostname


#### Base Command

`f5-asm-resource-hostnames-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to update hostname in. | Required | 
| name | Host name to update | Required | 
| include_subdomains | Whether or not to include subdomains | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.ResourceHostname.name | String | Policy hostname | 
| f5.ResourceHostname.id | String | Policy ID | 
| f5.ResourceHostname.created-by | String | Interface used to create the hostname | 
| f5.ResourceHostname.self-link | String | URI of specific hostname | 
| f5.ResourceHostname.include-subdomains | Boolean | Whether or not to include subdomains | 
| f5.ResourceHostname.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-resource-hostnames-update policy_name=Test_Policy name=qmasters.co include_subdomains=true```

#### Context Example
```
{
    "f5": {
        "resource-hostname": {
            "created-by": "GUI",
            "id": "dsblcoDkMkFb_A_H6BS6eA",
            "include-subdomains": true,
            "last-update": "2020-08-05T21:15:47Z",
            "name": "qmasters.co",
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0"
        }
    }
}
```

#### Human Readable Output

>### f5 information about hosts
>|id|name|created-by|include-subdomains|self-link|last-update|
>|---|---|---|---|---|---|
>| dsblcoDkMkFb_A_H6BS6eA | qmasters.co | GUI | true | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0 | 2020-08-05T21:15:47Z |


### f5-asm-resource-hostnames-delete
***
Delete a hostname from a policy


#### Base Command

`f5-asm-resource-hostnames-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of policy to delete from | Required | 
| name | Name of hostname to delete | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| f5.ResourceHostname.name | String | Policy hostname | 
| f5.ResourceHostname.id | String | Policy ID | 
| f5.ResourceHostname.created-by | String | Interface used to create the hostname | 
| f5.ResourceHostname.self-link | String | URI of specific hostname | 
| f5.ResourceHostname.include-subdomains | Boolean | Whether or not to include subdomains | 
| f5.ResourceHostname.last-update | String | Time of last update | 


#### Command Example
```!f5-asm-resource-hostnames-delete policy_name=Test_Policy name=qmasters.co```

#### Context Example
```
{
    "f5": {
        "resource-hostname": {
            "created-by": "GUI",
            "id": "dsblcoDkMkFb_A_H6BS6eA",
            "include-subdomains": true,
            "last-update": "2020-08-05T21:15:47Z",
            "name": "qmasters.co",
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0"
        }
    }
}
```

#### Human Readable Output

>### f5 information about hosts
>|id|name|created-by|include-subdomains|self-link|last-update|
>|---|---|---|---|---|---|
>| dsblcoDkMkFb_A_H6BS6eA | qmasters.co | GUI | true | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/host-names/dsblcoDkMkFb_A_H6BS6eA?ver=15.1.0 | 2020-08-05T21:15:47Z |


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
        "policy-cookies": [
            {
                "created-by": "GUI",
                "enforcement-type": "allow",
                "id": "E1g7FVU2CYuY30F-Rp_MUw",
                "is-base-64": false,
                "kind": "tm:asm:policies:cookies:cookiestate",
                "name": "yummy",
                "perform-staging": false,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/E1g7FVU2CYuY30F-Rp_MUw?ver=15.1.0"
            },
            {
                "created-by": "GUI",
                "enforcement-type": "allow",
                "id": "HeC08NE594GztN6H7bTecA",
                "is-base-64": false,
                "kind": "tm:asm:policies:cookies:cookiestate",
                "name": "yum",
                "perform-staging": false,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/HeC08NE594GztN6H7bTecA?ver=15.1.0"
            },
            {
                "created-by": "GUI",
                "enforcement-type": "allow",
                "id": "M4na42GvebBMnI5wV_YMxg",
                "is-base-64": false,
                "kind": "tm:asm:policies:cookies:cookiestate",
                "name": "*",
                "perform-staging": true,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/M4na42GvebBMnI5wV_YMxg?ver=15.1.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for policy cookies:
>|name|id|self-link|enforcement-type|perform-staging|kind|is-base-64|created-by|
>|---|---|---|---|---|---|---|---|
>| yummy | E1g7FVU2CYuY30F-Rp_MUw | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/E1g7FVU2CYuY30F-Rp_MUw?ver=15.1.0 | allow | false | tm:asm:policies:cookies:cookiestate | false | GUI |
>| yum | HeC08NE594GztN6H7bTecA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/HeC08NE594GztN6H7bTecA?ver=15.1.0 | allow | false | tm:asm:policies:cookies:cookiestate | false | GUI |
>| * | M4na42GvebBMnI5wV_YMxg | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/M4na42GvebBMnI5wV_YMxg?ver=15.1.0 | allow | true | tm:asm:policies:cookies:cookiestate | false | GUI |


### f5-asm-resource-blocking-settings-list
***
Retreive a BS list from a selected policy.


#### Base Command

`f5-asm-resource-blocking-settings-list`
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
```!f5-asm-resource-blocking-settings-list policy_name=Test_Policy endpoint=evasions```

#### Context Example
```
{
    "f5": {
        "resource-blocking-settings": [
            {
                "alarm": null,
                "block": null,
                "description": "Bad unescape",
                "enabled": false,
                "id": "9--k-GSum4jUNSf0sU91Dw",
                "kind": "tm:asm:policies:blocking-settings:evasions:evasionstate",
                "last-update": "2020-08-05T20:58:49Z",
                "learn": true,
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
>| 9--k-GSum4jUNSf0sU91Dw | Bad unescape | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/9--k-GSum4jUNSf0sU91Dw?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| Ahu8fuILcRNNU-ICBr1v6w | Apache whitespace | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Ahu8fuILcRNNU-ICBr1v6w?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| EKfN2XD-E1z097tVwOO1nw | Bare byte decoding | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/EKfN2XD-E1z097tVwOO1nw?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| dtxhHW66r8ZswIeccbXbXA | IIS Unicode codepoints | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/dtxhHW66r8ZswIeccbXbXA?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| 6l0vHEYIIy4H06o9mY5RNQ | IIS backslashes | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/6l0vHEYIIy4H06o9mY5RNQ?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| Y2TT8PSVtqudz407XG4LAQ | %u decoding | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/Y2TT8PSVtqudz407XG4LAQ?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| x02XsB6uJX5Eqp1brel7rw | Multiple decoding | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/x02XsB6uJX5Eqp1brel7rw?ver=15.1.0 | 2020-08-05T20:58:49Z |
>| qH_2eaLz5x2RgaZ7dUISLA | Directory traversals | false | true | tm:asm:policies:blocking-settings:evasions:evasionstate | https://localhost/mgmt/tm/asm/sub-violations/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0 | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/blocking-settings/evasions/qH_2eaLz5x2RgaZ7dUISLA?ver=15.1.0 | 2020-08-05T20:58:49Z |


### f5-asm-resource-blocking-settings-update
***
Update a BS element


#### Base Command

`f5-asm-resource-blocking-settings-update`
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
```!f5-asm-resource-blocking-settings-update ```

#### Human Readable Output



### f5-asm-resource-urls-list
***
List all policy URLs


#### Base Command

`f5-asm-resource-urls-list`
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
```!f5-asm-resource-urls-list policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "resource-url": [
            {
                "clickjacking-protection": false,
                "description": "",
                "id": "Q6tL31BrUl-vlY0yKsNSqA",
                "is-allowed": true,
                "last-update": "2020-08-05T21:16:50Z",
                "mandatory-body": false,
                "method": "*",
                "name": "/validation",
                "perform-staging": false,
                "protocol": "https",
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0",
                "type": "explicit"
            },
            {
                "clickjacking-protection": false,
                "description": "",
                "id": "faiefv884qtHRU3Qva2AbQ",
                "is-allowed": true,
                "last-update": "2020-08-05T20:58:51Z",
                "mandatory-body": false,
                "method": "*",
                "name": "*",
                "perform-staging": true,
                "protocol": "http",
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/faiefv884qtHRU3Qva2AbQ?ver=15.1.0",
                "type": "wildcard"
            },
            {
                "clickjacking-protection": false,
                "description": "",
                "id": "N_a3D1S7OKDehYEPb-mgCg",
                "is-allowed": true,
                "last-update": "2020-08-05T20:58:51Z",
                "mandatory-body": false,
                "method": "*",
                "name": "*",
                "perform-staging": true,
                "protocol": "https",
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/N_a3D1S7OKDehYEPb-mgCg?ver=15.1.0",
                "type": "wildcard"
            }
        ]
    }
}
```

#### Human Readable Output

>### URL for selected policy
>|id|name|protocol|type|method|is-allowed|clickjacking-protection|perform-staging|mandatory-body|self-link|last-update|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Q6tL31BrUl-vlY0yKsNSqA | /validation | https | explicit | * | true | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0 | 2020-08-05T21:16:50Z |
>| faiefv884qtHRU3Qva2AbQ | * | http | wildcard | * | true | false | true | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/faiefv884qtHRU3Qva2AbQ?ver=15.1.0 | 2020-08-05T20:58:51Z |
>| N_a3D1S7OKDehYEPb-mgCg | * | https | wildcard | * | true | false | true | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/N_a3D1S7OKDehYEPb-mgCg?ver=15.1.0 | 2020-08-05T20:58:51Z |



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
        "policy-cookies": {
            "created-by": "GUI",
            "enforcement-type": "allow",
            "id": "7t_U2dbYEAQp89Wp0m_QoA",
            "is-base-64": false,
            "name": "new_cookie",
            "perform-staging": false,
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0",
            "type": "explicit"
        }
    }
}
```

#### Human Readable Output

>### f5 data for adding policy cookies:
>|name|id|self-link|enforcement-type|perform-staging|type|is-base-64|created-by|
>|---|---|---|---|---|---|---|---|
>| new_cookie | 7t_U2dbYEAQp89Wp0m_QoA | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/cookies/7t_U2dbYEAQp89Wp0m_QoA?ver=15.1.0 | allow | false | explicit | false | GUI |


### f5-asm-resource-urls-add
***
Add a new URL to a policy


#### Base Command

`f5-asm-resource-urls-add`
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
```!f5-asm-resource-urls-add policy_name=Test_Policy protocol=https name=validation```

#### Context Example
```
{
    "f5": {
        "resource-url": {
            "clickjacking-protection": false,
            "description": "",
            "id": "Q6tL31BrUl-vlY0yKsNSqA",
            "is-allowed": true,
            "last-update": "2020-08-05T21:16:50Z",
            "mandatory-body": false,
            "method": "*",
            "name": "/validation",
            "perform-staging": false,
            "protocol": "https",
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0",
            "type": "explicit"
        }
    }
}
```

#### Human Readable Output

>### URL for selected policy
>|id|name|protocol|type|method|is-allowed|clickjacking-protection|perform-staging|mandatory-body|self-link|last-update|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Q6tL31BrUl-vlY0yKsNSqA | /validation | https | explicit | * | true | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/Q6tL31BrUl-vlY0yKsNSqA?ver=15.1.0 | 2020-08-05T21:16:50Z |


### f5-asm-resource-urls-update
***
Update an existing policy URL


#### Base Command

`f5-asm-resource-urls-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy the URL is in | Required | 
| name | Name of the URL | Required | 
| perform_staging | Whether or not to stage the URL | Optional | 
| description | Optional new description for the URL | Optional | 
| mandatory_body | Whether or not to have a mandatory body | Optional | 
| clickjacking_protection | Whether or not to enable clickjacking protection. | Optional | 
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
```!f5-asm-resource-urls-update policy_name=Test_Policy  name=/validation```

#### Context Example
```
{
    "f5": {
        "resource-url": {
            "clickjacking-protection": false,
            "description": "",
            "id": "xRwehdjQeUIVcKaT8yjN6g",
            "is-allowed": true,
            "last-update": "2020-08-05T21:10:46Z",
            "mandatory-body": false,
            "method": "*",
            "name": "/validation",
            "perform-staging": false,
            "protocol": "http",
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/xRwehdjQeUIVcKaT8yjN6g?ver=15.1.0",
            "type": "explicit"
        }
    }
}
```

#### Human Readable Output

>### URL for selected policy
>|id|name|protocol|type|method|is-allowed|clickjacking-protection|perform-staging|mandatory-body|self-link|last-update|
>|---|---|---|---|---|---|---|---|---|---|---|
>| xRwehdjQeUIVcKaT8yjN6g | /validation | http | explicit | * | true | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/xRwehdjQeUIVcKaT8yjN6g?ver=15.1.0 | 2020-08-05T21:10:46Z |


### f5-asm-resource-urls-delete
***
Delete a URL from a policy


#### Base Command

`f5-asm-resource-urls-delete`
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
```!f5-asm-resource-urls-delete policy_name=Test_Policy  name=/validation```

#### Context Example
```
{
    "f5": {
        "resource-url": {
            "clickjacking-protection": false,
            "description": "",
            "id": "xRwehdjQeUIVcKaT8yjN6g",
            "is-allowed": true,
            "last-update": "2020-08-05T21:10:46Z",
            "mandatory-body": false,
            "method": "*",
            "name": "/validation",
            "perform-staging": false,
            "protocol": "http",
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/xRwehdjQeUIVcKaT8yjN6g?ver=15.1.0",
            "type": "explicit"
        }
    }
}
```

#### Human Readable Output

>### URL for selected policy
>|id|name|protocol|type|method|is-allowed|clickjacking-protection|perform-staging|mandatory-body|self-link|last-update|
>|---|---|---|---|---|---|---|---|---|---|---|
>| xRwehdjQeUIVcKaT8yjN6g | /validation | http | explicit | * | true | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/urls/xRwehdjQeUIVcKaT8yjN6g?ver=15.1.0 | 2020-08-05T21:10:46Z |


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
```!f5-asm-policy-cookies-update ```

#### Human Readable Output



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
```!f5-asm-policy-cookies-delete ```

#### Human Readable Output



### f5-asm-resource-whitelist-ips-list
***
List all whitelisted IPs for a policy


#### Base Command

`f5-asm-resource-whitelist-ips-list`
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
```!f5-asm-resource-whitelist-ips-list policy_name=Test_Policy```

#### Context Example
```
{
    "f5": {
        "policy-whitelist-ip": [
            {
                "block-requests": "policy-default",
                "description": "",
                "id": "4CuqTmGkqfI01diFbc2PJQ",
                "ignore-anomalies": false,
                "ip-address": "100.100.100.100",
                "ip-mask": "255.255.255.255",
                "last-update": "2020-08-05T21:13:09Z",
                "never-learn-requests": false,
                "never-log-requests": false,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/4CuqTmGkqfI01diFbc2PJQ?ver=15.1.0",
                "trusted-by-policy-builder": false
            },
            {
                "block-requests": "policy-default",
                "description": "",
                "id": "lbpOAL2E2f2C7qp7kiV3OA",
                "ignore-anomalies": false,
                "ip-address": "20.20.20.20",
                "ip-mask": "255.255.255.255",
                "last-update": "2020-08-05T21:13:38Z",
                "never-learn-requests": false,
                "never-log-requests": false,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/lbpOAL2E2f2C7qp7kiV3OA?ver=15.1.0",
                "trusted-by-policy-builder": false
            },
            {
                "block-requests": "policy-default",
                "description": "",
                "id": "Uey6PzyJhbb6Qm-w0RD__Q",
                "ignore-anomalies": false,
                "ip-address": "30.30.30.30",
                "ip-mask": "255.255.255.255",
                "last-update": "2020-08-05T21:13:48Z",
                "never-learn-requests": false,
                "never-log-requests": false,
                "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/Uey6PzyJhbb6Qm-w0RD__Q?ver=15.1.0",
                "trusted-by-policy-builder": false
            }
        ]
    }
}
```

#### Human Readable Output

>### f5 data for resource whitelisted IPs:
>|id|ip-address|ip-mask|block-requests|ignore-anomalies|never-log-requests|never-learn-requests|trusted-by-policy-builder|self-link|last-update|
>|---|---|---|---|---|---|---|---|---|---|
>| 4CuqTmGkqfI01diFbc2PJQ | 100.100.100.100 | 255.255.255.255 | policy-default | false | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/4CuqTmGkqfI01diFbc2PJQ?ver=15.1.0 | 2020-08-05T21:13:09Z |
>| lbpOAL2E2f2C7qp7kiV3OA | 20.20.20.20 | 255.255.255.255 | policy-default | false | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/lbpOAL2E2f2C7qp7kiV3OA?ver=15.1.0 | 2020-08-05T21:13:38Z |
>| Uey6PzyJhbb6Qm-w0RD__Q | 30.30.30.30 | 255.255.255.255 | policy-default | false | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/Uey6PzyJhbb6Qm-w0RD__Q?ver=15.1.0 | 2020-08-05T21:13:48Z |


### f5-asm-resource-whitelist-ips-add
***
Add a new whitelisted IP to a policy.


#### Base Command

`f5-asm-resource-whitelist-ips-add`
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
```!f5-asm-resource-whitelist-ips-add policy_name=Test_Policy ip_address=1.2.3.4```

#### Context Example
```
{
    "f5": {
        "policy-whitelist-ip": {
            "block-requests": "policy-default",
            "description": "",
            "id": "pwbUREF-1u-BDw9MrdisOA",
            "ignore-anomalies": false,
            "ip-address": "1.2.3.4",
            "ip-mask": "255.255.255.255",
            "last-update": "2020-08-05T21:17:05Z",
            "never-learn-requests": false,
            "never-log-requests": false,
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0",
            "trusted-by-policy-builder": false
        }
    }
}
```

#### Human Readable Output

>### f5 data for created resource whitelisted IP:
>|id|ip-address|ip-mask|block-requests|ignore-anomalies|never-log-requests|never-learn-requests|trusted-by-policy-builder|self-link|last-update|
>|---|---|---|---|---|---|---|---|---|---|
>| pwbUREF-1u-BDw9MrdisOA | 1.2.3.4 | 255.255.255.255 | policy-default | false | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0 | 2020-08-05T21:17:05Z |


### f5-asm-resource-whitelist-ips-update
***
Update an existing whitelisted IP.


#### Base Command

`f5-asm-resource-whitelist-ips-update`
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
```!f5-asm-resource-whitelist-ips-update policy_name=Test_Policy ip_address=1.2.3.4```

#### Context Example
```
{
    "f5": {
        "policy-whitelist-ip": {
            "block-requests": "policy-default",
            "description": "",
            "id": "pwbUREF-1u-BDw9MrdisOA",
            "ignore-anomalies": false,
            "ip-address": "1.2.3.4",
            "ip-mask": "255.255.255.255",
            "last-update": "2020-08-05T21:17:05Z",
            "never-learn-requests": false,
            "never-log-requests": false,
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0",
            "trusted-by-policy-builder": false
        }
    }
}
```

#### Human Readable Output

>### f5 data for updated resource whitelisted IP:
>|id|ip-address|ip-mask|block-requests|ignore-anomalies|never-log-requests|never-learn-requests|trusted-by-policy-builder|self-link|last-update|
>|---|---|---|---|---|---|---|---|---|---|
>| pwbUREF-1u-BDw9MrdisOA | 1.2.3.4 | 255.255.255.255 | policy-default | false | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0 | 2020-08-05T21:17:05Z |


### f5-asm-resource-whitelist-ips-delete
***
Delete an existing whitelisted IP from a policy.


#### Base Command

`f5-asm-resource-whitelist-ips-delete`
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
```!f5-asm-resource-whitelist-ips-delete policy_name=Test_Policy ip_address=1.2.3.4```

#### Context Example
```
{
    "f5": {
        "policy-whitelist-ip": {
            "block-requests": "policy-default",
            "description": "",
            "id": "pwbUREF-1u-BDw9MrdisOA",
            "ignore-anomalies": false,
            "ip-address": "1.2.3.4",
            "ip-mask": "255.255.255.255",
            "last-update": "2020-08-05T21:17:05Z",
            "never-learn-requests": false,
            "never-log-requests": false,
            "self-link": "https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0",
            "trusted-by-policy-builder": false
        }
    }
}
```

#### Human Readable Output

>### f5 data for deleted resource whitelisted IP:
>|id|ip-address|ip-mask|block-requests|ignore-anomalies|never-log-requests|never-learn-requests|trusted-by-policy-builder|self-link|last-update|
>|---|---|---|---|---|---|---|---|---|---|
>| pwbUREF-1u-BDw9MrdisOA | 1.2.3.4 | 255.255.255.255 | policy-default | false | false | false | false | https://localhost/mgmt/tm/asm/policies/kpD2qFaUlGAbw8RhN5IFQA/whitelist-ips/pwbUREF-1u-BDw9MrdisOA?ver=15.1.0 | 2020-08-05T21:17:05Z |

