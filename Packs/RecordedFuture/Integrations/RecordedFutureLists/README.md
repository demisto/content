Search and manage watchlists in Recorded Future
This integration was integrated and tested with version 1.1.1 of RecordedFutureLists

## Configure Recorded Future - Lists in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API URL | Default URL: https://api.recordedfuture.com/gw/xsoar/ | True |
| API Token |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### recordedfuture-lists-search

***
Search for lists in Recorded Future

#### Base Command

`recordedfuture-lists-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_names | Freetext name to search for. | Optional | 
| contains | Filter lists based on entity types, will only include lists with the entity types specified. Default value "" includes all types. Possible values are: entity, source, text, custom, ip, domain, tech_stack, industry, brand, partner, industry_peer, location, supplier, vulnerability, company, hash, operation, attacker, target, method. | Optional | 
| limit | Limits the amount of returned results. | Optional | 
| include | Include all search results. Default is to exclude all lists owned by the system user. Possible values are: all. | Optional | 

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
When adding IDs use the following for Recorded Future light entities:
+ IPaddress: "ip:x.x.x.x"
+ Domain: "idn:example.xyz"
+ Hash: "hash:examplehashvalue"
+ Email: "email:example@example.xyz"
+ Url: "url:https://example.xyz"

#### Base Command

`recordedfuture-lists-add-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Id of the list that should be added, can be found by running !recordedfuture-lists-search with the corresponding filters or in the Recorded Future portal. | Required | 
| entity_ids | Specific ids from Recorded Future separated by comma, For urls containing commas: replace comma with %2C. | Optional | 
| freetext_names | Freetext names will be matched to Recorded Future ids separated by comma, this alernative will add the best match in the Recorded Future data. For urls containing commas: escape with %2C. | Optional | 
| entity_type | Type of the entities that should be added. Use together with freetext_names to improve entity resolution. Possible values are: ip, domain, malware, url, hash, cve, company, person, product, industry, country, attack-vector, operation, mitre-identifier, malware-category. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.List.Entities.name | String | Name of the entity in the list | 
| RecordedFuture.List.Entities.type | String | The Recorded Future entity type resolved during the action | 
| RecordedFuture.List.Entities.id | String | Unique id of the entity in Recorded Future | 
| RecordedFuture.List.Entities.input_value | String | The value inputted to the command | 
| RecordedFuture.List.Entities.action_result | String | Entity specific result for the action | 

### recordedfuture-lists-remove-entities

***
Remove entities from a list. Separate entities with commas. "NOTE:" If entity type is specified, only one entity type can be added with each action.
When adding IDs use the following for Recorded Future light entities:
+ IPaddress: "ip:x.x.x.x"
+ Domain: "idn:example.xyz"
+ Hash: "hash:examplehashvalue"
+ Email: "email:example@example.xyz"
+ Url: "url:https://example.xyz"

#### Base Command

`recordedfuture-lists-remove-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | ID of the list that should be removed. Can be found by running !recordedfuture-lists-search with the corresponding filters or in the Recorded Future portal. | Required | 
| entity_ids | A comma-separated list of specific IDs from Recorded Future. For URLs containing commas, replace comma with %2C. | Optional | 
| freetext_names | A comma-separated list of freetext names to be matched to Recorded Future IDs. This will remove the best match in the Recorded Future data. For URLs containing commas, escape with %2C. | Optional | 
| entity_type | Type of the entities that should be removed. Use together with freetext_names to improve entity resolution. Possible values are: ip, domain, malware, url, hash, cve, company, person, product, industry, country, attack-vector, operation, mitre-identifier, malware-category. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.List.Entities.name | String | Name of the entity in the list | 
| RecordedFuture.List.Entities.type | String | The Recorded Future entity type resolved during the action. | 
| RecordedFuture.List.Entities.id | String | Unique ID of the entity in Recorded Future. | 
| RecordedFuture.List.Entities.input_value | String | The value inputted to the command. | 
| RecordedFuture.List.Entities.action_result | String | Entity specific result for the action. | 

### recordedfuture-lists-entities

***
Get the entities that are currently in the given lists.

#### Base Command

`recordedfuture-lists-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_ids | A comma-separated list of Recorded Future list IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.List.id | String | Unique ID of the list in Recorded Future. | 
| RecordedFuture.List.name | String | Name of the list in Recorded Future. | 
| RecordedFuture.List.type | String | Recorded Future entity type. | 
| RecordedFuture.List.Entities.name | String | Name of the entity in the list. | 
| RecordedFuture.List.Entities.type | String | The Recorded Future entity type resolved during the action. | 
| RecordedFuture.List.Entities.id | String | Unique ID of the entity in Recorded Future. | 