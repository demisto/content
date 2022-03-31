CyberChef is a web-application developed by GCHQ that's been called the “Cyber Swiss Army Knife”. 

## Configure CyberChef on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CyberChef.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://prod.apifor.io/) | URL or your CyberChef server or https://prod.apifor.io/ | True |
    | API Key | API key if you use https://prod.apifor.io/ | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyberchef-bake
***
Bake you recipe!


#### Base Command

`cyberchef-bake`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| input | input data to be used in baking. | Required | 
| recipe | recipe how to bake. use JSON formatting. For example:  {         "op": "to decimal",         "args": {             "delimiter": "Colon"         }     }. | Required | 
| outputType | Optional argument to define outputType. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberChef.Bake | string | Output of the bake | 


#### Command Example
``` !cyberchef-bake input="One, two, three, four." recipe="{\"op\": \"to decimal\"}"```

```!cyberchef-bake input="79 110 101 44 32 116 119 111 44 32 116 104 114 101 101 44 32 102 111 117 114 46" recipe="{\"op\": \"from decimal\"}" outputType=string```

#### Human Readable Output
![image](https://user-images.githubusercontent.com/72339940/138084891-3509076f-3491-4eab-b280-1707d2227d08.png)



### cyberchef-magic
***
CyberChef Magic function


#### Base Command

`cyberchef-magic`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| input | The input data for the recipe. Currently accepts strings. | Required | 
| args | Arguments for the magic operation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberChef.Magic | string | Output of the Magic operation | 


#### Command Example
```!cyberchef-magic input="79 110 101 44 32 116 119 111 44 32 116 104 114 101 101 44 32 102 111 117 114 46"```

#### Human Readable Output
![image](https://user-images.githubusercontent.com/72339940/138084951-8e8225a5-50d5-42df-904f-9c9d0981767a.png)


