RaDark Integration

This integration was integrated and tested with version 2 of RaDark

## Configure RaDark on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RaDark.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | API Key generated from RaDark by your user. | True |
    | First time fetching | Start fetching incidents from the specified time. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Monitor ID | Set your monitor ID in RaDark. | True |
    | Fetch incidents |  | False |
    | Incidents Fetch Interval |  | False |
    | Incident type |  | False |
    | Max incidents to fetch each fetching | Maximum supported: 1000 | False |
    | Incident types to fetch | Set which incident types to fetch from RaDark. | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### radark-incident-get-items
***
Fetch all items for an incident.


#### Base Command

`radark-incident-get-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The unique ID of an incident that requires enrichment. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Radark.itemDetails | unknown | Return the parsed items dictionary and the items as mrakdown table. | 


#### Command Example
```!radark-incident-get-items incident_id=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx```

#### Context Example
```json
{
    "Radark": {
        "itemDetails": {
            "items": [
                {
                    "Item ID": "<ITEM_ID>",
                    "Email": "testa@test.com",
                    "Domain": "test.com",
                    "Password": "-",
                    "Password Type": "-", 
                    "Service": "-"
                }
            ],
            "items_markdown": "|Item ID|Email|Domain|Password|Password Type|Service| \n |---|---|---|---|---|---|\n| <ITEM_ID> | testa@test.com | test.com | - | - | - |"
        }
    }
}
```

#### Human Readable Output
|Item ID|Email|Domain|Password|Password Type|Service|
|---|---|---|---|---|---|
| <ITEM_ID> | testa@test.com | test.com | - | - | - |

**Items and markdown table are flexible (base on incident type).* 

### radark-email-enrich
***
Search a specific email address to get all exposed leaked credentials collected by RaDark.


#### Base Command

`radark-email-enrich`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address tested for leaked credentials. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Radark.emailDetails | unknown | Return the parsed emails dictionary and the emails as mrakdown table. | 


#### Command Example
```!radark-email-enrich email=testa@test.com```

#### Context Example
```json
{
    "Radark": {
        "emailDetails": {
            "items": [
                {
                    "Date": "Thu Jan 12 19:43:00 2017",
                    "Domain": "test.com",
                    "Email": "testa@test.com",
                    "Password": "-",
                    "Password Type": "-",
                    "Service": "-",
                    "Source": "ss"
                }
            ],
            "items_markdown": "|Email|Domain|Password Type|Password|Service|Source|Date|\n|---|---|---|---|---|---|---|\n| testa@test.com | test.com | - | - | - | ss | Thu Jan 12 19:43:00 2017"
        }
    }
}
```

#### Human Readable Output

>|Email|Domain|Password Type|Password|Service|Source|Date|
>|---|---|---|---|---|---|---|
>| testa@test.com | test.com | - | - | - | ss | Thu Jan 12 19:43:00 2017 |


### radark-item-handle
***
Mark item as handled on RaDark.


#### Base Command

`radark-item-handle`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The unique ID of an item that should be marked as handled on RaDark. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!radark-item-handle item_id=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx```

#### Human Readable Output
'Item ID (xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx) marked as handled'


### radark-item-purchase
***
Request to purchase an item offered for sale on an automated store.


#### Base Command

`radark-item-purchase`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The unique ID of an item that should requires purchase. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!radark-item-purchase item_id=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx```

#### Human Readable Output
Bot ID (<BOT_ID>) marked for purchasing
