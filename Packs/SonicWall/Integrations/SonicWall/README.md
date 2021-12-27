Integration for SonicWall Firewalls using SonicOS API
This integration was integrated and tested with version xx of SonicWall

## Configure SonicWall on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SonicWall.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://example.net) | True |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sonicwall-add-ipv4-objects
***
Creates IPV4 Address Objects on Sonic Wall


#### Base Command

`sonicwall-add-ipv4-objects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ObjectPairs | A JSON Array of Objects containing attributes Value, Type, Name<br/><br/>{<br/>"Value": &lt;the_ip&gt;,<br/>"Type": "IP",<br/>"Name":&lt;object_name&gt;<br/>}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SonicWall.AddedObjects | Unknown | Objects Added To SonicWall | 


#### Command Example
``` ```

#### Human Readable Output



### sonicwall-get-ipv4-objects
***
Retrieve IPV4 Address Objects From Sonic Wall


#### Base Command

`sonicwall-get-ipv4-objects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SonicWall.IPV4Objects | Unknown |  | 
| SonicWall.IPV4Objects.Name | Unknown |  | 
| SonicWall.IPV4Objects.Value | Unknown |  | 
| SonicWall.IPV4Objects.UUID | Unknown |  | 
| SonicWall.IPV4Objects.Zone | Unknown |  | 


#### Command Example
``` ```

#### Human Readable Output


