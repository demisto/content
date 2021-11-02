Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet. Driven by Internet-wide scanning, Censys lets researchers find specific hosts and create aggregate reports on how devices, websites, and certificates are configured and deployed.
This integration was integrated and tested with version xx of Censys_copy

## Configure Censys_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Censys_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Censys API ID | True |
    | Censys API Secret | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cen-view
***
Returns detailed information for an IP address within the specified index.


#### Base Command

`cen-view`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | IP address for which to perform a query. | Required | 
| index | The index from which to retrieve data. Can be "ipv4", "websites", or "certificates". Possible values are: ipv4, websites, certificates. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cen-search
***
Searches for an attribute within the specified index.


#### Base Command

`cen-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The attribute for which you are searching (JSON format). | Required | 
| index | The index on which to perform a query. Possible values are: ipv4, websites, certificates. | Required | 
| page | Page to return (default 1). Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.Search.response.results | unknown | Censys Search Results | 
| Censys.metadata.pages | unknown | Censys Total Pages encountered | 
| Censys.metadata.page | unknown | Current Search Page | 


#### Command Example
``` ```

#### Human Readable Output


