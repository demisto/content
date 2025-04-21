This integration enables you to fetch incidents and manage your RaDark monitor from Cortex XSOAR.
This integration was integrated and tested with version 2 of RaDark

## Configure RaDark in Cortex


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

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### radark-incident-get-items
***
Fetch all items for an incident by the given incident ID.


#### Base Command

`radark-incident-get-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The unique ID of an incident that requires enrichment. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Radark.itemDetails.items.item_id | string | The ID of the item on RaDark. | 
| Radark.itemDetails.items.email | string | The email of the item. | 
| Radark.itemDetails.items.domain | string | The domain of the item. | 
| Radark.itemDetails.items.password | string | The password of the item. | 
| Radark.itemDetails.items.password_type | string | The password type of the item. | 
| Radark.itemDetails.items.source | string | The source of the item. | 
| Radark.itemDetails.items.service | string | The service of the item. | 
| Radark.itemDetails.items.dump_post_date | string | The dump post date of the item. | 
| Radark.itemDetails.items.compromised_website | string | The compromised website of the item. | 
| Radark.itemDetails.items.bot_id | string | The bot ID of the item. | 
| Radark.itemDetails.items.resource | string | The resource of the item. | 
| Radark.itemDetails.items.country | string | The country of the item. | 
| Radark.itemDetails.items.source_ip | string | The source IP of the item. | 
| Radark.itemDetails.items.infection_type | string | The infection type of the item. | 
| Radark.itemDetails.items.updated_date | string | The updated date of the item. | 
| Radark.itemDetails.items.username | string | The username of the item. | 
| Radark.itemDetails.items.additional_data | string | The additional data of the item. | 
| Radark.itemDetails.items.price | string | The price of the item. | 
| Radark.itemDetails.items.isp | string | The ISP of the item. |
| Radark.itemDetails.items.ip | string | The IP of the item. |
| Radark.itemDetails.items.hostname | string | The hostname of the item. |
| Radark.itemDetails.items.port | string | The port of the item. |
| Radark.itemDetails.items.technology | string | The technology of the item. |
| Radark.itemDetails.items.cve_details | string | The CVE details of the item. |
| Radark.itemDetails.items.details | string | The details of the item. |
| Radark.itemDetails.items.type | string | The type of the item. |
| Radark.itemDetails.items.description | string | The description of the item. |
| Radark.itemDetails.items.date | string | The date of the item. |
| Radark.itemDetails.items.bin | string | The bin of the item. |
| Radark.itemDetails.items.number | string | The number of the item. |
| Radark.itemDetails.items.tags | string | The tags of the item. |
| Radark.itemDetails.items.link | string | The link of the item. |
| Radark.itemDetails.items.context | string | The context of the item. |
| Radark.itemDetails.details | string | General details of the incident. | 


#### Command Example
```!radark-incident-get-items incident_id=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx```

#### Context Example
```json
{
    "Radark": {
        "itemDetails": {
            "items": [
                {
                    "item_id": "<ITEM_ID>",
                    "email": "testa@test.com",
                    "domain": "test.com",
                    "password": "-",
                    "password_type": "-", 
                    "service": "-"
                }
            ],
          "details": "Incident contains 44 items. Full details can be found on \"items\" tab."
        }
    }
}
```
**Items are flexible (base on incident type).* 

#### Human Readable Output

>No data found for item ID: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

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
| Radark.emailDetails.emails.email | string | The email to enrich from RaDark. | 
| Radark.emailDetails.emails.domain | string | The domain of the email. | 
| Radark.emailDetails.emails.password_type | string | The password type of the email. | 
| Radark.emailDetails.emails.password | string | The password of the email. | 
| Radark.emailDetails.emails.service | string | The service of the email. | 
| Radark.emailDetails.emails.source | string | The source of the email. | 
| Radark.emailDetails.emails.source | string | The posted date of the email. | 


#### Command Example
```!radark-email-enrich email=testa@test.com```

#### Context Example
```json
{
    "Radark": {
        "emailDetails": {
            "emails": [
                {
                    "date": "2017-01-12T19:43:00Z",
                    "domain": "test.com",
                    "email": "testa@test.com",
                    "password": "-",
                    "password_type": "-",
                    "service": "-",
                    "source": "ss"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>|Email|Domain|Password Type|Password|Service|Source|Date|
>|---|---|---|---|---|---|---|
>| testa@test.com | test.com | - | - | - | ss | 2017-01-12T19:43:00Z |


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
``` ```

#### Human Readable Output
>Item ID (xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx) marked as handled


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

>Bot ID (<BOT_ID>) marked for purchasing