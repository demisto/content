Darktrace is a Cyber AI platform for threat detection and response across cloud, email, industrial, and the network.
This integration was integrated and tested with version 6.0.0 of Darktrace

## Configure Darktrace in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| isFetch | Fetch incidents | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| public_api_token | Public API Token | True |
| private_api_token | Private API Token | True |
| min_score | Minimum Score | True |
| max_alerts | Maximum Model Breaches per Fetch | False |
| first_fetch | First fetch time | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### darktrace-get-model-breach

***
darktrace-get-model-breach returns a model breach based on its model breach id (pbid)


#### Base Command

`darktrace-get-model-breach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Model breach ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach.pbid | Number | Model breach ID | 
| Darktrace.ModelBreach.time | Date | Model breach generated time. | 
| Darktrace.ModelBreach.commentCount | Number | Number of comments on the model breach | 
| Darktrace.ModelBreach.score | Number | Score of Darktrace model breach \(0 to 1\) | 
| Darktrace.ModelBreach.device.did | Number | Darktrace device ID of Device that breached the model | 
| Darktrace.ModelBreach.device.macaddress | String | MAC address of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.device.vendor | String | Vendor of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.device.ip | String | IP of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.device.hostname | String | Hostname of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.device.devicelabel | String | Device label of the device involved in the model breach \(if applicable\) | 
| Darktrace.ModelBreach.model.name | String | Darktrace model that was breached | 
| Darktrace.ModelBreach.model.pid | Number | Model ID of the model that was breached | 
| Darktrace.ModelBreach.model.uuid | String | Model UUID of the model that was breached | 
| Darktrace.ModelBreach.model.tags | Unknown | List of model tags for the model that was breached | 
| Darktrace.ModelBreach.model.priority | Number | Priority of the model that was breached \(0 to 5\) | 
| Darktrace.ModelBreach.model.description | String | Darktrace model description | 


#### Command Example

```!darktrace-get-model-breach pbid=95```

#### Context Example

```
{
    "Darktrace": {
        "ModelBreach": {
            "commentCount": 0,
            "device": {
                "devicelabel": "Kelly's Laptop",
                "did": 823,
                "hostname": "sf-l-kjohnson",
                "ip": "172.31.32.146",
                "macaddress": "06:42:04:c2:b0:48",
                "vendor": "HP"
            },
            "model": {
                "description": "A device is connecting to watched domains or IP addresses. The watch list can be edited from the main GUI menu, Intel sub-menu, under the icon Watched Domains.\\n\\nAction: Review the domain and IP being connected to.",
                "name": "Compromise::Watched Domain",
                "pid": 762,
                "priority": 5,
                "tags": ["AP: C2 Comms"],
                "uuid": "3338210a-8979-4a1b-8039-63ca8addf166"
            },
            "pbid": 95,
            "score": 1,
            "time": "2020-10-08T21:11:21.000Z"
        }
    }
}
```

#### Human Readable Output

>### Darktrace Model Breach 95

>|commentCount|device|model|pbid|score|time|
>|---|---|---|---|---|---|
>| 0 | did: 823<br/>macaddress: 0a:df:4b:52:64:7a<br/>vendor: HP<br/>ip: 172.31.32.146<br/>hostname: ip-172-31-32-146<br/>devicelabel: Kelly's Laptop | name: Compromise::Watched Domain<br/>pid: 762<br/>uuid: 3338210a-8979-4a1b-8039-63ca8addf166<br/>tags: \[AP: C2 Comms\]<br/>priority: 5<br/>description: A device is connecting to watched domains or IP addresses. The watch list can be edited from the main GUI menu, Intel sub-menu, under the icon Watched Domains. | 95 | 1 | 2020-10-08T21:11:21.000Z |


### darktrace-get-model-breach-comments

***
Returns the comments on a model breach based on its model breach id (pbid)


#### Base Command

`darktrace-get-model-breach-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Model Breach ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach.Comment.message | Unknown | comments on Model Breach | 
| Darktrace.ModelBreach.pbid | Unknown | Model breach identifier | 
| Darktrace.ModelBreach.Comment.username | Unknown | Commented by user | 
| Darktrace.ModelBreach.Comment.time | Unknown | Comment timestamp |

#### Command Example

```!darktrace-get-model-breach-comments pbid=46```

#### Context Example

```
{
    "Darktrace": {
        "ModelBreach": {
            "comments": [
                {
                    "message": "Flag for follow-up",
                    "pbid": 46,
                    "pid": 210,
                    "time": "2020-10-08T21:11:21.000Z",
                    "username": "user.one"
                },
                {
                    "message": "Activity has been remediated",
                    "pbid": 46,
                    "pid": 210,
                    "time": "2020-10-08T23:11:21.000Z",
                    "username": "user.two"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Darktrace Model Breach 46 Comments

>|message|pbid|pid|time|username|
>|---|---|---|---|---|
>| Flag for follow-up | 46 | 210 | 2020-10-08T21:11:21.000Z | user.one |
>| Activity has been remediated | 46 | 210 | 2020-10-08T23:11:21.000Z | user.two |


### darktrace-acknowledge-model-breach

***
Acknowledge a model breach as specified by Model Breach ID


#### Base Command

`darktrace-acknowledge-model-breach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Model Breach ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach.acknowledged | String | Whether the model breach is acknowledged in Darktrace | 
| Darktrace.ModelBreach.pbid | Number | Model breach ID |
| Darktrace.ModelBreach.acknowledged.response| Number | Message response from acknowledge action |


#### Command Example

```!darktrace-acknowledge-model-breach pbid=111```

#### Context Example

```
{
    "Darktrace": {
        "ModelBreach": {
            "acknowledged": true,
            "pbid": 111
        }
    }
}
```

#### Human Readable Output

>### Model Breach 111 Acknowledged

>|response|
>|---|
>| Successfully acknowledged. |


### darktrace-unacknowledge-model-breach

***
Unacknowledges a model breach as specified by Model Breach ID


#### Base Command

`darktrace-unacknowledge-model-breach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Darktrace model breach ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach.acknowledged | String | Whether the model breach is acknowledged | 
| Darktrace.ModelBreach.pbid | Number | Model breach ID |
| Darktrace.ModelBreach.acknowledged.response | String | Message response from acknowledge action |


#### Command Example

```!darktrace-unacknowledge-model-breach pbid=111```

#### Context Example

```
{
    "Darktrace": {
        "ModelBreach": {
            "acknowledged": false,
            "pbid": 111
        }
    }
}
```

#### Human Readable Output

>### Model Breach 111 Unacknowledged

>|response|
>|---|
>| Successfully unacknowledged. |

### darktrace-get-model-breach-connections

***
Returns connections encountered by the device during a model breach.

#### Base Command

`darktrace-get-model-breach-connections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Darktrace model breach ID | Required | 
| endtime | Endtime of data retrieved | Not Required | 
| count | The amount of lines returned | Not Required | 
| offset | The offset of data pulled | Not Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach| Dictionary | Details of the model breach |

### darktrace-get-model

***
Returns a model given a UUID

#### Base Command

`darktrace-get-model`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Darktrace model ID | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.Model | Dictionary | Details of the model |


### darktrace-get-model-component

***
Returns the details of a component given a CID

#### Base Command

`darktrace-get-model-component`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | Darktrace components ID | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.Model.Component | Dictionary | Details of the component |


### darktrace-post-comment-to-model-breach

***
Posts a specified comment to a model breach.

#### Base Command

`darktrace-post-comment-to-model-breach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pbid | Darktrace model breach unique identifier | Required |
| message | Comment message | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.ModelBreach.commented | String | Whether the model breach is commented in Darktrace |
| Darktrace.ModelBreach.pbid | Number | Model breach ID |
| Darktrace.ModelBreach.message | String | Comment content |
| Darktrace.ModelBreach.response | String | Message response from comment action |