Add and remove domains in Cisco OpenDNS.
This integration was integrated and tested with version 1.0 of Cisco Umbrella Enforcement.
Supported Cortex XSOAR versions: 5.0.0 and later.

## Configure Cisco Umbrella Enforcement in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://example.net\) | True |
| api_key | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### umbrella-domain-event-add
***
Posts a malware event to the API for processing and optionally adding to a customer's domain lists.


#### Base Command

`umbrella-domain-event-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_time | Alert time of the new event in datetime format, e.g., 2013-02-08T09:30:26.0Z. | Required | 
| device_id | Device ID of the new event. | Required | 
| destination_domain | Destination domain of the new event. | Required | 
| destination_url | Destination URL of the new event. | Required | 
| device_version | Device version for the new event. | Required | 
| destination_ip | The destination IP address of the domain, specified in IPv4 dotted-decimal notation e.g., '8.8.8.8'. | Optional | 
| event_severity | The partner threat level or rating, e.g., severe, bad, high, and so on. | Optional | 
| event_type | Common name or classification of the threat. | Optional | 
| event_description | Variant or other descriptor of the event type. | Optional | 
| file_name | Path to the file exhibiting malicious behavior. | Optional | 
| file_hash | SHA-1 of file reported by the appliance. | Optional | 
| source | IP/Host of the infected computer/device that was patient 0 for the event. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!umbrella-domain-event-add alert_time=2013-02-08T09:30:26.0Z device_id=ba6a58f4-e692-4724-ba36-c28132c761de destination_domain=test6.com device_version=13.7a destination_url=test6.com```

#### Context Example
```json
{}
```

#### Human Readable Output

>New event was added successfully, The Event id is 31bb0adb,8f27,4423,a081-3b5773260f87.

### umbrella-domains-list
***
List of domains.


#### Base Command

`umbrella-domains-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Number of page to return. Default is "1". | Optional | 
| limit | The maximum number of queries per page. Default is "50". Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UmbrellaEnforcement.Domains.name | String | Name of the domains. | 
| UmbrellaEnforcement.Domains.id | Number | ID of the domains. | 
| UmbrellaEnforcement.Domains.IsDeleted | Boolean | True if the domain has been deleted from list. | 


#### Command Example
```!umbrella-domains-list```

#### Context Example
```json
{
    "UmbrellaEnforcement": {
        "Domains": [
            {
                "IsDeleted": false,
                "id": 3569571,
                "name": "test6.com"
            },
            {
                "IsDeleted": false,
                "id": 3790609,
                "name": "test7.com"
            },
            {
                "IsDeleted": false,
                "id": 3912159,
                "name": "test8.com"
            },
            {
                "IsDeleted": false,
                "id": 3912161,
                "name": "test9.com"
            },
            {
                "IsDeleted": false,
                "id": 54637170,
                "name": "badinterner4.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### List of Domains
>|id|name|
>|---|---|
>| 3569571 | test6.com |
>| 3790609 | test7.com |
>| 3912159 | test8.com |
>| 3912161 | test9.com |
>| 54637170 | badinterner4.com |


### umbrella-domain-delete
***
Delete domain.


#### Base Command

`umbrella-domain-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the domain. | Optional | 
| name | Name of the domain. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!umbrella-domain-delete name=test6.com```

#### Context Example
```json
{}
```

#### Human Readable Output

>test6.com domain was removed from block list