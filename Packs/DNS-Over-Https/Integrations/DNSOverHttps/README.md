Query dns names over https from Cloudflare or Google
This integration was integrated and tested with version xx of DNS-over-https

## Configure DNS-over-https on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DNS-over-https.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | DNS over HTTPS resolver | Select Cloudflare or Google DNS over HTTPS server to use | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### doh-resolve
***
Resolve an name to IP over HTTPS


#### Base Command

`doh-resolve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | domain you want to resolve to IP. | Required | 
| type | Type of DNS records you want to get. Possible values are: A, AAAA, TXT, MX, DNSKEY, NS. Default is A. | Optional | 
| only_answers | If you only want to return the answers. Possible values are: True, False. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNS-over-HTTPS.Results | unknown | DNS query results | 


#### Command Example
``` ```

#### Human Readable Output


