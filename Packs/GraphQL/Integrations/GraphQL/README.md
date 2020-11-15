Generic GraphQL client to interact with any GraphQL server API.

## Configure GraphQL on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GraphQL.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | GraphQL Server URL \(e.g. https://countries.trevorblades.com\) | True |
| credentials | Username | False |
| headers | HTTP Headers | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
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
| outputs_key_field | Primary key field in the response to unique the object in the context data. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!graphql-query query=`{country(code: "BR"){name}}````

#### Context Example
```json
{
    "GraphQL": {
        "country": {
            "name": "Brazil"
        }
    }
}
```

#### Human Readable Output

>### Results
>|country|
>|---|
>| name: Brazil |

