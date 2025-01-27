Collect logs from 3rd party vendors.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Generic Event Collector (Beta) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident type |  | False |
| Server URL |  | True |
| Endpoint | Add the endpoint you want to collect data from \(Alert/Events Etc..\) | True |
| Authentication Type | Select the authentication method | True |
| HTTP Method |  | True |
| API Token | API Token | False |
| Username |  | False |
| Password |  | False |
| Add Fields To header | If the product authentication requires more fields to add to the header please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Request Parameters | If the product authentication requires more fields to add to the DATA please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Query Parameters | If the product authentication allows to filter the results using query Parameters please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Initial Query Parameters | If the product requires a different initial query parameters for the first fetch call, please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Is pagination Needed |  |  |
| Pagination Field Name |  | False |
| Pagination Flag | Flag examples: \{has_more: True\}, \{next: True\} etc | False |
| Timestamp format of the event creation time. | e.g. "%Y-%m-%dT%H:%M:%S.%fZ" or "%Y.%m.%d %H:%M:%S" | False |
| Timestamp field | The name of the event creation time in the response data, e.g. "timestamp" or "created_at". | True |
| Events lookup path in the response JSON, dot seperated, e.g. "data.items". | Where within the response object to find the events list. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Vendor | Enter vendor name for dataset | True |
| Product | Enter product name for dataset | True |
| First fetch time |  | True |
| Fetch Events |  | False |
| Events Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### generic-event-collector-get-events

***
Gets events from 3rd party vendor.

#### Base Command

`generic-event-collector-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Optional | 

#### Context Output

There is no context output for this command.
