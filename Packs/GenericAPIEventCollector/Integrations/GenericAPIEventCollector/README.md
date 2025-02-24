The **Generic API Event Collector** allows you to ingest data from any API endpoint into Cortex.
By configuring this collector, you can gather data from various systems and bring it into the Cortex ecosystem for better analysis and correlation.

Note: This pack is currently in **Beta**, and as such, it may be subject to future changes and may not work on all types of APIs and Authentication.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Generic API Event Collector (Beta) in Cortex


| **Parameter**                                                              | **Description**                                                                                                                                                                                                                                                                            | **Required** |
|----------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Server URL                                                                 |                                                                                                                                                                                                                                                                                            | True         |
| Endpoint                                                                   | Add the endpoint you want to collect data from \(Alert/Events Etc..\)                                                                                                                                                                                                                      | True         |
| Authentication Type                                                        | Select the authentication method                                                                                                                                                                                                                                                           | True         |
| HTTP Method                                                                | The HTTP method of the request to the API.                                                                                                                                                                                                                                                 | True         |
| API Token                                                                  | API Key to access the service REST API.                                                                                                                                                                                                                                                    | False        |
| Username                                                                   | Username &amp;amp; Password to use for basic authentication.                                                                                                                                                                                                                               | False        |
| Password                                                                   |                                                                                                                                                                                                                                                                                            | False        |
| Add Fields To header                                                       | If the product authentication requires more fields to add to the header please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\}                | False        |
| Use system proxy settings                                                  |                                                                                                                                                                                                                                                                                            | False        |
| Trust any certificate (not secure)                                         |                                                                                                                                                                                                                                                                                            | False        |
| Vendor                                                                     | Enter vendor name for dataset                                                                                                                                                                                                                                                              | True         |
| Product                                                                    | Enter product name for dataset                                                                                                                                                                                                                                                             | True         |
| Request data                                                               | If the product authentication requires more fields to add to the DATA please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\}                  | False        |
| Initial request data                                                       | If the product requires a different initial DATA,  please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\}                                     | False        |
| Request JSON parameters                                                    | If the product authentication requires more fields to add to the body as JSON please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\}          | False        |
| Initial request JSON parameters                                            | If the product requires a different initial request JSON, please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\}                              | False        |
| Query parameters                                                           | If the product authentication allows to filter the results using query Parameters please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\}      | False        |
| Initial query parameters                                                   | If the product requires a different initial query parameters for the first fetch call, please add it here in a dictionary format \{unique_field : 286\} if there's a need to add more then one use it in this format: \{'field-1': value_example, 'field-2': value_2, 'field-3': value_3\} | False        |
| Is pagination needed                                                       | If the API JSON response supports events pagination.                                                                                                                                                                                                                                       |              |
| Pagination field name                                                      | Next page field in JSON response, e.g., "cursor", "next_page"                                                                                                                                                                                                                              | False        |
| Pagination flag                                                            | Next page existence in JSON response e.g., "has_more", "next"                                                                                                                                                                                                                              | False        |
| Timestamp format of the event creation time or "epoch".                    | Python compatible datetime formatting \(e.g. "%Y-%m-%dT%H:%M:%S.%fZ" or "%Y.%m.%d %H:%M:%S"\) or "epoch" to use UNIX epoch time.                                                                                                                                                           | False        |
| Timestamp field                                                            | The name of the event creation time in the response data, e.g. "timestamp" or "created_at".                                                                                                                                                                                                | True         |
| Events lookup path in the response JSON, dot seperated, e.g. "data.items". | Where within the response object to find the events list.                                                                                                                                                                                                                                  | False        |
| Event ID lookup path in the event response JSON, dot seperated, e.g. "id". | Where within the event object to find the events id.                                                                                                                                                                                                                                       | False        |
| The type of ID field, either "integer" or "string"                         | ID field of type integer are comparable and when last fetched id is the maximum ID between the fetched events, when the type is string, the last fetched ID is the last event returned from the API.                                                                                       | False        |
| OK codes                                                                   | Allowed HTTP status codes for successful response from the API                                                                                                                                                                                                                             | False        |
| Limit                                                                      | Number of incidents to fetch per fetch.                                                                                                                                                                                                                                                    | False        |
| Fetch Events                                                               |                                                                                                                                                                                                                                                                                            | False        |
| Events Fetch Interval                                                      |                                                                                                                                                                                                                                                                                            | False        |

How to configure the event collector
---

### Authentication
You must specify the authentication method required by the server. 
The supported authentication types include:
1. Basic authentication (username and password)
2. Token-based authentication
3. Bearer token
4. Api-Key token
5. Raw Token (for custom token-based authentication)
6. No Authorization (for publicly accessible data)

### Pagination

When the API supports pagination in the response, the collector can fetch more pages of data using the below parameters
1. Is pagination needed If the API JSON response supports events pagination.
2. Pagination field name, Next page field in JSON response, e.g., "cursor" or "next_page" | False |
3. Pagination flag, The Next page existence in JSON response e.g., "has_more" or "next"

In the below example the pagination flag is `pagination.has_more`
The pagination field name is `pagination.next_page`
```json
{
    "data": [
        {
            "id": 1,
            "name": "John Doe",
            "occupation": "Software Engineer"
        },
        {
            "id": 2,
            "name": "Jane Smith",
            "occupation": "Data Scientist"
        }
    ],
    "pagination": {
        "current_page": 1,
        "next_page": "https://api.example.com/users?page=2",
        "has_more": true
    }
}
```

### Request Data (And initial request data)
If the product authentication requires more fields to add to the `DATA`.
Please add it here in a dictionary format.

For example:
```json
{"field-1": "value_example", "field-2": 1, "field-3": "value_3"}
```
Note: Using the initial request data parameter will only be used in the first request to collect events.
### Request JSON (And initial request JSON)
If the product authentication requires more fields to add to the body as JSON, please add it 
here in a dictionary format.

For example:
```json
{"date": "2021-08-01", "field-2": 1, "field-3": "value_3"}
```

Note: Using the initial request JSON parameter will only be used in the first request to collect events.

### Query parameters (And Initial Query parameters)
If the product authentication allows filtering the results using query parameters, please add it here in a dictionary format:
```json
{"ordering": "id", "limit": 1, "created_after": "@first_fetch_datetime"}
```

Note: Using the initial query parameters parameter will only be used in the first request to collect events.


### Timestamp field
The name of the event creation time in the response data, e.g. "timestamp" or "created_at".
In the following API response:
```json
{
  "data": [
    {
      "id": 3,
      "name": "Alice Brown",
      "occupation": "Network Engineer",
      "created": "2021-10-05T19:45:20.789012Z"
    },
    {
      "id": 4,
      "name": "Dave Wilson",
      "occupation": "Cybersecurity Analyst",
      "created": "2021-10-06T10:15:45.654321Z"
    }
  ],
  "pagination": {
    "current_page": 2,
    "next_page": "https://api.example.com/users?page=3",
    "has_more": true
  }
}
```
the timestamp field is `created`

### Timestamp format
The timestamp format of the event creation time or "epoch" to use UNIX epoch time.
The formatting supported is Python-compatible datetime formatting (e.g. "%Y-%m-%dT%H:%M:%S.%fZ" or "%Y.%m.%d %H:%M:%S").
In the following API response:
```json
{
  "data": [
    {
      "id": 3,
      "name": "Alice Brown",
      "occupation": "Network Engineer",
      "created": "2021-10-05T19:45:20.789012Z"
    },
    {
      "id": 4,
      "name": "Dave Wilson",
      "occupation": "Cybersecurity Analyst",
      "created": "2021-10-06T10:15:45.654321Z"
    }
  ],
  "pagination": {
    "current_page": 2,
    "next_page": "https://api.example.com/users?page=3",
    "has_more": true
  }
}
```
The timestamp format is python format "%Y-%m-%dT%H:%M:%S.%fZ"

Note: To learn more about Python date and time formats, see: https://docs.python.org/3/library/datetime.html#format-codes 

### Events
Where within the response JSON to search for the events, dot seperated (e.g. "data.items").

Example 1:
```json
{
  "data": [
    {
      "id": 4,
      "name": "Alice Brown",
      "occupation": "Network Engineer",
      "created": "2021-10-05T19:45:20.789012Z"
    },
    {
      "id": 3,
      "name": "Dave Wilson",
      "occupation": "Cybersecurity Analyst",
      "created": "2021-10-06T10:15:45.654321Z"
    }
  ]
}
```
The events are within the "data" in the response.

Example 1:
```json
{
  "data": {
    "items": [
        {
            "id": 4,
            "name": "Alice Brown",
            "occupation": "Network Engineer",
            "created": "2021-10-05T19:45:20.789012Z"
        },
        {
            "id": 3,
            "name": "Dave Wilson",
            "occupation": "Cybersecurity Analyst",
            "created": "2021-10-06T10:15:45.654321Z"
        }
    ]
  }
}
```
The events are within the "data.items" in the response.

### Event ID & Type
Event ID lookup path in the event response JSON, dot seperated, e.g. "id"
Where within the event object to find the events' id.

The type of ID field, either "integer" or "string":
- ID field of type integer is comparable, and when last fetched id is the maximum ID between the fetched events.
- ID field of the type is string, the last fetched ID is the last event returned from the API.
  
Example 1:
```json
{
  "data": [
    {
      "id": 4,
      "name": "Alice Brown",
      "occupation": "Network Engineer",
      "created": "2021-10-05T19:45:20.789012Z"
    },
    {
      "id": 3,
      "name": "Dave Wilson",
      "occupation": "Cybersecurity Analyst",
      "created": "2021-10-06T10:15:45.654321Z"
    }
  ],
  "pagination": {
    "current_page": 2,
    "next_page": "https://api.example.com/users?page=3",
    "has_more": true
  }
}
```
The event id field should be "id" and the type should be integer, and the last fetched id will be 4.

Example 2:
```json
{
  "data": [
    {
      "uuid": "123e4567-e89b-12d3-a456-426614174000",
      "name": "Alice Brown",
      "occupation": "Network Engineer",
      "created": "2021-10-05T19:45:20.789012Z"
    },
    {
      "uuid": "123e4567-e89b-12d3-a456-426614174001",
      "name": "Dave Wilson",
      "occupation": "Cybersecurity Analyst",
      "created": "2021-10-06T10:15:45.654321Z"
    }
  ],
  "pagination": {
    "current_page": 2,
    "next_page": "https://api.example.com/users?page=3",
    "has_more": true
  }
}
```
The event id field should be "uuid" and the type should be string, and the last fetched id will be "123e4567-e89b-12d3-a456-426614174001".

## Substitutions in API requests calls
To make the API calls more dynamic against the API endpoint, we added a few placeholders that will be substituted before calling the API endpoint.
1. `@last_fetched_id` - The last id that was fetched from the API, if this is the first fetch, the value will be empty.
2. `@last_fetched_datetime` - The last fetched event time from the API, if this is the first fetch, the value will be empty.
3. `@first_fetch_datetime` - The first fetch time, when the integration first started to fetch events.
4. `@fetch_size_limit` - The number of incidents to fetch per fetch.

Examples being used in query parameters:
- This will substitute the `@last_fetched_id` with the last fetched id from a previous fetch call.
```json
{"ordering": "id", "limit": 100, "id__gt": "@last_fetched_id"}
```
The resulting API query parameters will be:
```json
{"ordering": "id", "limit": 100, "id__gt": "4"}
```

- This will substitute the `@first_fetch_datetime` with the first fetch time.
```json
{"ordering": "id", "limit": 1, "created_after": "@first_fetch_datetime"}
```
The resulting API query parameters will be:
```json
{"ordering": "id", "limit": 1, "created_after": "2021-10-06T10:15:45.654321Z"}
```

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### generic-api-event-collector-get-events

***
Gets events from 3rd-party vendor.

#### Base Command

`generic-api-event-collector-get-events`

#### Input

| **Argument Name**  | **Description**                                                                                                                   | **Required** |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------|--------------|
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required     | 
| limit              | Maximum number of results to return.                                                                                              | Optional     | 

#### Context Output

There is no context output for this command.
