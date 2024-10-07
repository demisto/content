Acalvio ShadowPlex is a comprehensive Autonomous Deception Platform that offers Advanced Threat Detection, Investigation and Response capabilities.
This integration was integrated and tested with Acalvio ShadowPlex 5.x and ShadowPlex API 2.0.
## Configure Acalvio ShadowPlex in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Acalvio API Server URL \(e.g. https://example.net\) | True |
| apikey | Acalvio API Key | True |
| insecure | Trust SSL certificate | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### acalvio-is-deception-host
***
Check if its a Deception Host


#### Base Command

`acalvio-is-deception-host`


#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | Hostname or IP Address of Endpoint | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Acalvio.IsDeceptionHost.is_deception | Boolean | Returns 'True' if Host is a Deception else 'False' | 
| Acalvio.IsDeceptionHost.host | String | Host to be checked if Deception | 


#### Command Example

`!acalvio-is-deception-host host="10.10.10.10"`


#### Context Example
```
{
    'is_deception': true, 
    'host': '10.10.10.10'
}
```


#### Human Readable Output
>Results - Deception Host
>
>| __Key__ | __Value__ |
>| --- | --- |
>| is_deception | true |
>| host | 10.10.10.10 |
>



### acalvio-is-deception-user
***
Check if its a Deception User


#### Base Command

`acalvio-is-deception-user`


#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username of the Domain User | Required | 
| domain | AD Domain Name to which User belongs to | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Acalvio.IsDeceptionUser.is_deception | Boolean | Returns 'True' if its a Deception User else 'False' | 
| Acalvio.IsDeceptionUser.username | String | Username to be checked if Deception | 
| Acalvio.IsDeceptionUser.domain | String | Users Domain | 


#### Command Example

`!acalvio-is-deception-user username="tom" domain="acalvio.com"`


#### Context Example
```
{
    'is_deception': true, 
    'username': 'tom',
    'domain': 'acalvio.com'
}
```


#### Human Readable Output
>Results - Deception User
> 
>| __Key__ | __Value__ |
>| --- | --- |
| is_deception | true |
| username  | dmusernonadmin2 |
| domain | acalvio.com |



### acalvio-is-deception-file
***
Check if its a Deception File on the Endpoint


#### Base Command

`acalvio-is-deception-file`


#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | Hostname or IP Address of Endpoint where file resides | Required | 
| filename | Name of the file to be checked | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Acalvio.IsDeceptionFile.is_deception | Boolean | Returns 'True' if File is a Deception else 'False' | 
| Acalvio.IsDeceptionFile.filename | String | Filename to be checked if Deception | 
| Acalvio.IsDeceptionFile.endpoint | String | Hostname or IP Address of Endpoint where file resides | 


#### Command Example

`!acalvio-is-deception-file endpoint="win10-ep" filename="t33.pdf"`


#### Context Example
```
{
    'is_deception': true, 
    'filename': 't33.pdf',
    'endpoint': 'win10-ep'
}
```


#### Human Readable Output
>Results - Deception File
>
>| __Key__ | __Value__ |
>| --- | --- |
| is_deception | true |
| filename  | t33.pdf |
| endpoint | win10-ep |



### acalvio-mute-deception-host
***
Mute a Deception Host


#### Base Command

`acalvio-mute-deception-host`


#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | Deception Host to be Muted | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Acalvio.MuteDeceptionHost.is_mute | Boolean | Returns 'True' if Deception is Muted else 'False' | 
| Acalvio.MuteDeceptionHost.host | String | Deception Host to be Muted |  


#### Command Example

`acalvio-mute-deception-host host="win10-host"`


#### Context Example
```
{
    'is_mute': true, 
    'host': 'win10-host'
}
```


#### Human Readable Output
>Results - Mute Deception
>
>| __Key__ | __Value__ |
>| --- | --- |
| is_mute | true |
| host | win10-host |



### acalvio-unmute-deception-host
***
Unmute a Deception Host


#### Base Command

`acalvio-unmute-deception-host`


#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | Deception Host to be Unmuted | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Acalvio.UnmuteDeceptionHost.is_unmute | Boolean | Returns 'True' if Deception is Unmuted else 'False' | 
| Acalvio.UnmuteDeceptionHost.host | String | Deception Host to be Unmuted |  


#### Command Example

`acalvio-unmute-deception-host host="win10-host"`


#### Context Example
```
{
    'is_unmute': true, 
    'host': 'win10-host'
}
```


#### Human Readable Output
>Results - Unute Deception
>
>| __Key__ | __Value__ |
>| --- | --- |
| is_unmute | true |
| host | win10-host |



### acalvio-mute-deception-on-endpoint
***
Mute a Deception on Endpoint


#### Base Command

`acalvio-mute-deception-on-endpoint`


#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | Hostname or IP Address of Endpoint | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Acalvio.MuteDeceptionEndpoint.is_mute | Boolean | Returns 'True' if Deception is Muted else 'False' | 
| Acalvio.MuteDeceptionEndpoint.endpoint | String | Hostname or IP Address of Endpoint |  


#### Command Example

`acalvio-mute-deception-on-endpoint endpoint="win10-ep"`


#### Context Example
```
{
    'is_mute': true, 
    'endpoint': 'win10-ep'
}
```


#### Human Readable Output
>Results - Mute Deception
>
>| __Key__ | __Value__ |
>| --- | --- |
| is_mute | true |
| endpoint | win10-ep |



### acalvio-unmute-deception-on-endpoint
***
Unmute a Deception on Endpoint


#### Base Command

`acalvio-unmute-deception-on-endpoint`


#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | Hostname or IP Address of Endpoint | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Acalvio.UnmuteDeceptionEndpoint.is_unmute | Boolean | Returns 'True' if Deception is Unmuted else 'False' | 
| Acalvio.UnmuteDeceptionEndpoint.endpoint | String | Hostname or IP Address of Endpoint |  


#### Command Example

`acalvio-unmute-deception-on-endpoint endpoint="win10-ep"`


#### Context Example
```
{
    'is_unmute': true, 
    'endpoint': 'win10-ep'
}
```


#### Human Readable Output
>Results - Unmute Deception
>
>| __Key__ | __Value__ |
>| --- | --- |
| is_unmute | true |
| endpoint | win10-ep |
