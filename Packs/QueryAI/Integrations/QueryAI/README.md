## Query.AI
Query.AI is a decentralized data access and analysis technology that simplifies security investigations across disparate platforms, without data duplication.

In order to use this integration you need the following:
1. The URL of Query.AI Proxy component (see below)
2. An account registered with [Query.AI](https://app.query.ai) belonging to your Organization
3. The API token associated with above account
4. Platform Connection Details of any platform integrated via Query.AI you wish to connect to (This can be overridden while executing commands)

#### BASE_URL
The base URL would be of the [Query.AI Proxy](https://proxy.query.ai:443) . Replace with hostname and port of the Query.AI Proxy component running in your environment.

## Configure Query.AI in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Query.AI Proxy URL | True |
| api_token | Query.AI API token | True |
| alias | Default Platform Alias to retrieve data | True |
| connection_params | Default Connection params as JSON object. Eg - {"platform_alias":{"username":"my_username","password":"my_password"}} | True |
| timeout | Request Timeout (in seconds). Default value is 60 seconds but it may take longer time to retrieve data based upon your data platform. | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |



## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. [Returns response for the query being run on Query.AI: queryai-run-query](#1-queryai-run-query)

### 1. queryai-run-query
************************
Returns response for the query being run on Query.AI.

##### Base Command
  
`queryai-run-query`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search Query. | Required |
| alias | Platform Alias. | Optional |
| connection_params | Connection params as JSON object. Eg- {"alias":{"username":"my_username","password":"my_password"}}. | Optional |
| workflow_params | Workflow params as JSON object. Eg- {"param1":"value1","param2":"value2"}. | Optional |
| time_text | Search time period. | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QueryAI.query.result | Unknown | Response after running query. |
| QueryAI.query.markdown_string | String | Readable Response after running query. |

##### Command Example

`!queryai-run-query query="run workflow my_workflow" alias="my_alias" connection_params="{\"my_alias\":{\"username\":\"my_username\",\"password\":\"my_password\"}}" workflow_params="{\"param1\":\"value1\",\"param2\":\"value2\"}" time_text="search 1 year ago to now"`
##### Context Example

```json
{
    "QueryAI": {
        "query": {
            "markdown_string": "### Query.AI Result for the query: run workflow my_workflow\n|agegroupbin|agegroupdesc|\n|---|---|\n| 2 | 18-19 |\n| 3 | 20-21 |\n### Click here to [see details](https://app.query.ai/login;questions=run%20workflow%20my_workflow;alias=my_alias;queryDuration=search%201%20year%20ago%20to%20now;params=%7B%22param1%22%3A%22value1%22%2C%22param2%22%3A%22value2%22%7D;)",
            "result": [
                {
                    "agegroupbin": 2,
                    "agegroupdesc": "18-19"
                },
                {
                    "agegroupbin": 3,
                    "agegroupdesc": "20-21"
                }
            ]
        }
    }
}
```

##### Human Readable Output
***************************

### Query.AI Result for the query: run workflow my_workflow
|agegroupbin|agegroupdesc|
|---|---|
| 2 | 18-19 |
| 3 | 20-21 |
### Click here to [see details](https://app.query.ai/login;questions=run%20workflow%20my_workflow;alias=my_alias;queryDuration=search%201%20year%20ago%20to%20now;params=%7B%22param1%22%3A%22value1%22%2C%22param2%22%3A%22value2%22%7D;)
****************************

## Support

For any other assistance or feedback, feel free to [contact us](mailto:support@query.ai).