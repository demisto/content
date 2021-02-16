Generic GraphQL client to interact with any GraphQL server API.

## Configure GraphQL on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GraphQL.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | GraphQL Server URL \(e.g. https://countries.trevorblades.com\) | True |
| credentials | Username / Header Name | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Authentication
The **Username** and **Password** integration parameters can be used to access server that require basic authentication.

These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field, and the header value in the **Password** field.


## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### graphql-query
***
Execute a query request to the GraphQL server.


#### Base Command

`graphql-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The GraphQL query to execute. | Required |
| variables_names | A comma-separated list of names, for example: "foo","bar","alpha". | Optional |
| variables_values | A comma-separated list of values, for example: 7,"foo",3. | Optional |
| max_result_size | Max result size in KBs. Default is 10. | Optional |
| populate_context_data | Whether to populate the result to the context data. Possible values are: true, false. Default is true. | Optional |
| outputs_key_field | Primary key field in the response to unique the object in the context data. | Optional |

#### Command Example
```!graphql-query query="query getContinentName ($code: ID!) {continent (code: $code) {name}}" variables_names="code" variables_values="EU"````

#### Context Example
```json
{
    "GraphQL": {
        "continent": {
            "name": "Europe"
        }
    }
}
```

#### Human Readable Output

>### GraphQL Query Results
>|continent|
>|---|
>| name: Europe |

### graphql-mutation
***
Execute a mutation request to the GraphQL server.


#### Base Command

`graphql-mutation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The GraphQL mutation to execute. | Required |
| variables_names | A comma-separated list of names, for example: "foo","bar","alpha". | Optional |
| variables_values | A comma-separated list of values, for example: 7,"foo",3. | Optional |
| max_result_size | Max result size in KBs. Default is 10. | Optional |
| populate_context_data | Whether to populate the result to the context data. Possible values are: true, false. Default is true. | Optional |
| outputs_key_field | Primary key field in the response to unique the object in the context data. | Optional |

#### Command Example
```!graphql-mutation query="mutation {createMessage(input: {author: \"Jon Doe\",content: \"knowledge is the most powerful thing on earth, harvest it and use it wisely\",}) {id}}"````

#### Context Example
```json
{
    "GraphQL": {
        "createMessage": {
            "id": "76a9df0b02f2cc624fc9"
        }
    }
}
```

#### Human Readable Output

>### GraphQL Query Results
>|createMessage|
>|---|
>| id: 76a9df0b02f2cc624fc9 |

