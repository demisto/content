Collect logs from 3rd party vendors.

## Configure Generic Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident type |  | False |
| Vendor | Enter vendor name for dataset | True |
| Product | Enter product name for dataset | True |
| Server URL |  | True |
| Endpoint | Add the endpoint you want to collect data from \(Alert/Events Etc..\) | True |
| Authentication Type | Select the authentication method | True |
| HTTP Method |  | True |
| Token | 3rd party token / 3rd party API key | False |
| Password |  | False |
| Username |  | False |
| Password |  | False |
| Add Fields To header | If the product authentication requires more fields to add to the header please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Request Parameters | If the product authentication requires more fields to add to the DATA please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Query Parameters   | If the product authentication allowes to filter the results using query Parameters please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False |
| Is pagination Needed |  |  |
| Pagination Field Name |  | False |
| Pagination Flag | Flag examples: \{has_more: True\}, \{next: True\} etc | False |
| Connection Test Type | Pick connection if you just want to make sure the authentication is working. Pick push_to_dataset if you want to see the data from the endpoint in your dataset | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| First fetch time |  | True |
| Fetch Events |  | False |
| Events Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fetch-events

***
Manual command to fetch and display events. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and exceeding the API request limitation.

#### Base Command

`fetch-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 

#### Context Output

There is no context output for this command.
