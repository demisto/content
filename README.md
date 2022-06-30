This integration provides TAXII2 Services for system indicators (Outbound feed).
This integration was integrated and tested with version xx of TAXII2 Server

## Configure TAXII2 Server on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for TAXII2 Server.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Long Running Instance |  | False |
    | TAXII2 Server version |  | True |
    | Listen Port | Will run the TAXII2 server on this port from within Cortex XSOAR. Requires a unique port for each long-running integration instance. Do not use the same port for multiple instances. | True |
    | Username | Credentials to use for the basic auth. | False |
    | Password |  | False |
    | Collection JSON | JSON string of indicator query collections. Dictionary of the collection name as the key and the query as the value. | True |
    | Cortex XSOAR Extension fields | Comma-separated fields to return in the extension. Leave empty for no extension fields, 'All' for all existing fields. | False |
    | Response Size | Maximum number of items to return. | True |
    | Certificate (Required for HTTPS) |  | False |
    | Private Key (Required for HTTPS) |  | False |
    | TAXII2 Service URL Address | Full URL address to set in the TAXII2 service response. If not set, the integration will try to auto-detect the URL. | False |
    | NGINX Global Directives | NGINX global directives to be passed on the command line using the -g option. Each directive should end with \`;\`. For example: \`worker_processes 4; timer_resolution 100ms;\`. Advanced configuration to be used only if instructed by Cortex XSOAR Support. | False |
    | NGINX Server Conf | NGINX server configuration. To be used instead of the default NGINX_SERVER_CONF used in the integration code. Advanced configuration to be used only if instructed by Cortex XSOAR Support. | False |
    | STIX types for STIX indicator Domain Object | Choose which STIX Cyber Observable Object provides as STIX Domain Object of 'indicator' | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### taxii-server-list-collections
***
Returns all the collections


#### Base Command

`taxii-server-list-collections`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TAXIIServer.Collection.id | String | The collection id | 
| TAXIIServer.Collection.query | String | The collection query | 
| TAXIIServer.Collection.title | String | The collection title | 
| TAXIIServer.Collection.description | String | The collection description | 

#### Command example
```!taxii-server-list-collections```
#### Context Example
```json
{
    "TAXIIServer": {
        "Collection": {
            "can_read": true,
            "can_write": false,
            "description": "",
            "id": "2eb7bfae-7739-5863-9b00-1681309c3d8c",
            "media_types": [
                "application/stix+json;version=2.1"
            ],
            "query": "",
            "title": "ALL"
        }
    }
}
```

#### Human Readable Output

>### Collections
>|id|title|query|description|
>|---|---|---|---|
>| 2eb7bfae-7739-5863-9b00-1681309c3d8c | ALL |  |  |


### taxii-server-info
***
Returns the TAXII server info, default URL, title, etc.


#### Base Command

`taxii-server-info`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TAXIIServer.Info.title | String | The server title | 
| TAXIIServer.Info.api_roots | Unknown | The server api roots urls | 
| TAXIIServer.Info.default | String | The default url | 
| TAXIIServer.Info.description | String | The server description | 

#### Command example
```!taxii-server-info```
#### Context Example
```json
{
    "TAXIIServer": {
        "ServerInfo": {
            "api_roots": [
                "https://foo.cooo.com/inc/threatintel/"
            ],
            "default": "https://foo.cooo.com/inc/threatintel/",
            "description": "This integration provides TAXII Services for system indicators (Outbound feed).",
            "title": "Cortex XSOAR TAXII2 Server"
        }
    }
}
```

#### Human Readable Output

>**In case the default URL is incorrect, you can override it by setting "TAXII2 Service URL Address" field in the integration configuration**
>
>### Server Info
>|api_roots|default|description|title|
>|---|---|---|---|
>| https:<span>//</span>foo.cooo.com/inc/threatintel/ | https:<span>//</span>foo.cooo.com/inc/threatintel/ | This integration provides TAXII Services for system indicators (Outbound feed). | Cortex XSOAR TAXII2 Server |

