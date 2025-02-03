Collect logs from 3rd party vendors using API.
This integration was integrated and tested with version xx of GenericAPIEventCollector.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Generic API Event Collector (Beta) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Endpoint | Add the endpoint you want to collect data from \(Alert/Events Etc..\) | True |
| Authentication Type | Select the authentication method | True |
| HTTP Method | The HTTP method of the request to the API. | True |
| API Token | API Key to access the service REST API. | False |
| Username | Username &amp;amp; Password to use for basic authentication. | False |
| Password |  | False |
| Add Fields To header | If the product authentication requires more fields to add to the header please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Vendor | Enter vendor name for dataset | True |
| Product | Enter product name for dataset | True |
| Request data | If the product authentication requires more fields to add to the DATA please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Initial request data | If the product requires a different initial DATA,  please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Request JSON parameters | If the product authentication requires more fields to add to the body as JSON please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Initial request JSON parameters | If the product requires a different initial request JSON, please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Query parameters | If the product authentication allows to filter the results using query Parameters please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Initial query parameters | If the product requires a different initial query parameters for the first fetch call, please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Is pagination needed | If the API JSON response supports events pagination. |  |
| Pagination field name | Next page field in JSON response, e.g., "cursor", "next_page" | False |
| Pagination flag | Next page existence in JSON response e.g., "has_more", "next" | False |
| Timestamp format of the event creation time or "epoch". | Python compatible datetime formatting \(e.g. "%Y-%m-%dT%H:%M:%S.%fZ" or "%Y.%m.%d %H:%M:%S"\) or "epoch" to use UNIX epoch time. | False |
| Timestamp field | The name of the event creation time in the response data, e.g. "timestamp" or "created_at". | True |
| Events lookup path in the response JSON, dot seperated, e.g. "data.items". | Where within the response object to find the events list. | False |
| Event ID lookup path in the event response JSON, dot seperated, e.g. "id". | Where within the event object to find the events id. | False |
| The type of ID field, either "integer" or "string" | ID field of type integer are comparable and when last fetched id is the maximum ID between the fetched events, when the type is string, the last fetched ID is the last event returned from the API. | False |
| First fetch time |  | True |
| Fetch Events |  | False |
| Events Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### generic-api-event-collector-get-events

***
Gets events from 3rd party vendor.

#### Base Command

`generic-api-event-collector-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Optional | 

#### Context Output

There is no context output for this command.
