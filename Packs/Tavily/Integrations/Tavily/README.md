Tavily is a web service that provides real-time web search and retrieval capabilities through an API, enabling
developers to fetch and extract relevant information from the internet in structured formats like JSON.

## Configure Tavily in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The API Key to use for the connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tavily-extract

***
Extracts its content from the given url.

#### Base Command

`tavily-extract`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The url to extract its content. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tavily.URL | string | The give url to extract its content. | 
| Tavily.Content | string | The extracted content from the given url. | 
