Search and manage watchlists in Recorded Future
This integration was integrated and tested with version 1.0 of RecordedFutureLists

## Configure Recorded Future - Lists on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Recorded Future - Lists.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API URL | Default URL: https://api.recordedfuture.com/gw/xsoar/ | True |
    | API Token |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### recordedfuture-lists-search

***
Search for lists in Recorded Future

#### Base Command

`recordedfuture-lists-search`
`recordedftuure-lists-search list_names="ip,domain" contains="entity"`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_names | Freetext name to search for. | Optional | 
| contains | Filter lists based on entity types, will only include lists with the entity types specified. Default value "" includes all types. Possible values are: entity, source, text, custom, ip, domain, tech_stack, industry, brand, partner, industry_peer, location, supplier, vulnerability, company, hash, operation, attacker, target, method. | Optional | 
| limit | Limits the amount of returned results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.List.id | String | Unique id of the list in Recorded Future | 
| RecordedFuture.List.name | String | Name of the list in Recorded Future | 
| RecordedFuture.List.type | String | Recorded future entity type | 
| RecordedFuture.List.created | String | Timestamp of creation | 
| RecordedFuture.List.updated | String | Timestamp of last update to the list | 
| RecordedFuture.List.owner_id | String | Unique id of the owner in Recorded Future | 
| RecordedFuture.List.owner_name | String | Readable name of list in Recorded Future | 

### recordedfuture-lists-add-entities

***
Add entities to a list, separate entities by commas. "NOTE:" if entity type is specified, only one entity type can be added with each action.

#### Base Command

`recordedfuture-lists-add-entities list_id="Some list id" entity_ids="ip:1.1.1.1,idn:some.com"`  
`recordedfuture-lists-add-entities list_id="Some list id" freetext_names="1.1.1.1" entity_type="ip"`  
`recordedfuture-lists-add-entities list_id="Some list id" freetext_names="1.1.1.1,8.8.8.8" entity_type="ip"`  
`recordedfuture-lists-add-entities list_id="Some list id" freetext_names="some.com" entity_type="domain"`  

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Id of the list that should be added, can be found by running !recordedfuture-lists-search with the corresponding filters or in the Recorded Future portal. | Required | 
| entity_ids | Specific ids from Recorded Future separated by comma, For urls containing commas: replace comma with %2C. | Optional | 
| freetext_names | Freetext names will be matched to Recorded Future ids separated by comma, this alernative will add the best match in the Recorded Future data. For urls containing commas: escape with %2C. | Optional | 
| entity_type | Type of the entities that should be added, only used together with freetext_names to improve entity resolving. Possible values are: ip, domain, malware, url, hash, cve, company, person, product, industry, country, attack-vector, operation, mitre-identifier, malware-category. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.List.Entities.name | String | Name of the entity in the list | 
| RecordedFuture.List.Entities.type | String | The Recorded Future entity type resolved during the action | 
| RecordedFuture.List.Entities.id | String | Unique id of the entity in Recorded Future | 
| RecordedFuture.List.Entities.input_value | String | The value inputted to the command | 
| RecordedFuture.List.Entities.action_result | String | Entity specific result for the action | 
