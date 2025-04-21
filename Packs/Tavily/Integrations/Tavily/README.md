Tavily is a web service that provides real-time web search and retrieval capabilities through an API, enabling developers to fetch and extract relevant information from the internet in structured formats like JSON.
This integration was integrated and tested with version xx of Tavily.

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

### extract

***

#### Base Command

`extract`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | Comma-separated list of urls to extract. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tavily | list | List of dictionaries with URL and Content keys, both strings. | 
