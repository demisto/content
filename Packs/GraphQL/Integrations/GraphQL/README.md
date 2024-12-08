Generic GraphQL client to interact with any GraphQL server API.

## Configure GraphQL in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | GraphQL Server URL \(e.g. https://api.github.com/graphql\) | True |
| credentials | Username / Header Name | False |
| fetch_schema_from_transport | Fetch the schema from the transport | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |


## Authentication
The **Username** and **Password** integration parameters can be used to access server that require basic authentication.

These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field, and the header value in the **Password** field.

For example, in order to use
[GitHub GraphQL API](https://docs.github.com/en/graphql), the parameters
should be set as follows:

- ***Username*** : `_header:Authorization`
- ***Password*** : `bearer <PERSONAL-ACCESS-TOKEN>`

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| variables_names | A comma-separated list of names, for example: flag,num,alpha | Optional |
| variables_values | A comma-separated list of values, for example: true,4,3.5 | Optional |
| variables_types | An optional comma-separated list of types, for example: boolean,number,number. Optional values are: string, boolean and number. If not provided, integers and booleans will be detected automatically, and the rest of the variables will be handled as strings. | Optional |
| max_result_size | Max result size in KBs. Default is 10. | Optional |
| populate_context_data | Whether to populate the result to the context data. Possible values are: true, false. Default is true. | Optional |
| outputs_key_field | Primary key field in the response to unique the object in the context data. | Optional |

#### Command Example

```!graphql-query query="query($number_of_repos:Int!) {viewer {name repositories(last: $number_of_repos) { nodes { name } } } }" variables_names="number_of_repos" variables_values="3" variables_types="Int" max_result_size="10" populate_context_data="true"````

#### Context Example
```json
{
    "GraphQL": {
        "viewer": {
            "repositories": {
                "nodes": [
                    {
                        "name": "content"
                    },
                    {
                        "name": "demisto-sdk"
                    },
                    {
                        "name": "content-docs"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### GraphQL Query Results
>| viewer |
>|---|
>| repositories: {"nodes": [{"name": "content"}, {"name": "demisto-sdk"}, {"name": "content-docs"}]} |

### graphql-mutation
***
Execute a mutation request to the GraphQL server.


#### Base Command

`graphql-mutation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The GraphQL mutation to execute. | Required |
| variables_names | A comma-separated list of names, for example: flag,num,alpha | Optional |
| variables_values | A comma-separated list of values, for example: true,4,3.5 | Optional |
| variables_types | An optional comma-separated list of types, for example: boolean,number,number. Optional values are: string, boolean and number. If not provided, integers and booleans will be detected automatically, and the rest of the variables will be handled as strings. | Optional |
| max_result_size | Max result size in KBs. Default is 10. | Optional |
| populate_context_data | Whether to populate the result to the context data. Possible values are: true, false. Default is true. | Optional |
| outputs_key_field | Primary key field in the response to unique the object in the context data. | Optional |

#### Command Example
```!graphql-mutation query="mutation AddReactionToIssue {addReaction(input:{subjectId:"MDU6SXNzdWUyMzEzOTE1NTE=",content:HOORAY}) {reaction {content} subject { id } } }" max_result_size="10" populate_context_data="true"````

#### Context Example
```json
{
    "GraphQL": {
        "addReaction": {
            "reaction": {
                "content": "HORRAY"
            },
            "subject": {
                "id": "MDU6SXNzdWUyMzEzOTE1NTE="
            }
        }
    }
}
```

#### Human Readable Output

>### GraphQL Query Results
>| addReaction |
>|---|
>| reaction: {"content": "HOORAY"}<br/>subject: {"id": "MDU6SXNzdWUyMzEzOTE1NTE="} |

## Troubleshooting
  - If you are encountering the error `GraphQLError: Cannot query field`, you may be failing because of a schema validation error. Uncheck the **Fetch the schema from the transport** integration parameter to disable the schema validation.