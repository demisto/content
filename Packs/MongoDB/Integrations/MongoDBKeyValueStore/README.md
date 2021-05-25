## Overview
---

Manipulates key/value pairs according to an incident utilizing the MongoDB collection.
This integration was integrated and tested with version v4.2.3 of MongoDB.

The account user must have appropriate permissions -  ***root*** role to execute the API calls.


## Configure MongoDB Key Value Store on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for MongoDB Key Value Store.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __MongoDB username__
    * __URI (mongodb://IP/FQDN:Port Number)__
    * __MongoDB database name__
    * __MongoDB collection name__
    * __Use an SSL/TLS secured connection__
    * __Trust any certificate (not secure)__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. mongodb-write-key-value
2. mongodb-get-key-value
3. mongodb-list-key-values
4. mongodb-delete-key
5. mongodb-purge-entries
6. mongodb-get-keys-number
7. mongodb-list-incidents
### 1. mongodb-write-key-value
---
Adds a key/value record for the incident. If the key exists, the existing value is overwritten.*
##### Base Command

`mongodb-write-key-value`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The XSOAR incident number. | Optional | 
| key | Name/Key. | Required | 
| value | Assigns a value to the name/key. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MongoDB.Entry.ID | String | Entry ID. | 
| MongoDB.Entry.Incident | String | Incident ID. | 
| MongoDB.Entry.Key | String | Incident key. | 
| MongoDB.Entry.Value | String | Incident value. | 
| MongoDB.Entry.Modified | Date | Incident modified date. | 


##### Command Example
```!mongodb-write-key-value key=demisto value=test5```

##### Context Example
```
{
    "MongoDB.Entry": {
        "Incident": "6e1807d3-b0ae-40a0-8e82-dad33539c587", 
        "Value": "test5", 
        "ID": "5e92db8a225a4976e096eeb9", 
        "Key": "demisto", 
        "Modified": "2020-04-12T09:12:42+00:00"
    }
}
```

##### Human Readable Output
Incident "6e1807d3-b0ae-40a0-8e82-dad33539c587" - key/value collection - 1 document added

### 2. mongodb-get-key-value
---
Returns the value of the specified name/key of an incident.
##### Base Command

`mongodb-get-key-value`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The XSOAR incident number. | Optional | 
| key | Name/Key. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MongoDB.Entry.Incident | String | Incident ID. | 
| MongoDB.Entry.Key | String | Incident key. | 
| MongoDB.Entry.Value | String | The value of the key. | 


##### Command Example
```!mongodb-get-key-value key=demisto```

##### Context Example
```
{
    "MongoDB.Entry": {
        "Incident": "6e1807d3-b0ae-40a0-8e82-dad33539c587", 
        "Value": "test5", 
        "Modified": "2020-04-12T09:12:42+00:00", 
        "Key": "demisto"
    }
}
```

##### Human Readable Output
### The key and value that is stored for the incident
|Incident|Key|Modified|Value|
|---|---|---|---|
| 6e1807d3-b0ae-40a0-8e82-dad33539c587 | demisto | 2020-04-12T09:12:42+00:00 | test5 |


### 3. mongodb-list-key-values
---
Lists the keys and their values for the specified incident.
##### Base Command

`mongodb-list-key-values`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The XSOAR incident number. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MongoDB.Incident.Incident | String | Incident ID. | 
| MongoDB.Incident.Key | String | Incident key. | 
| MongoDB.Incident.Value | String | The value of the key. | 


##### Command Example
```!mongodb-list-key-values id=1234```

##### Context Example
```
{
    "MongoDB.Incident": [
        {
            "Incident": "1234", 
            "Value": "test2", 
            "Key": "test"
        }, 
        {
            "Incident": "1234", 
            "Value": "test", 
            "Key": "demisto"
        }, 
        {
            "Incident": "1234", 
            "Value": "world", 
            "Key": "hello"
        }
    ]
}
```

##### Human Readable Output
### The key/value paires stored in incident 1234
|Key|Value|
|---|---|
| test | test2 |
| demisto | test |
| hello | world |


### 4. mongodb-delete-key
---
Deletes the key/value record for an incident.
##### Base Command

`mongodb-delete-key`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The XSOAR incident number. | Optional | 
| key | Name/Key. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-delete-key key=hello id=1234```

##### Human Readable Output
Incident "1234" - key/value collection - 1 document deleted

### 5. mongodb-purge-entries
---
Purges all keys/values for an incident. A common use case for this command is when closing an incident. This command clears the entries for the closed incident from the database.
##### Base Command

`mongodb-purge-entries`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The XSOAR incident number. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-purge-entries id=2468```

##### Human Readable Output
Incident "2468" key/value pairs purged - 1 document/record deleted

### 6. mongodb-get-keys-number
---
Returns the number of key/value pairs for an incident.
##### Base Command

`mongodb-get-keys-number`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The XSOAR incident number. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-get-keys-number id=1234```

##### Human Readable Output
The count of the key/value pairs for the incident - 2

### 7. mongodb-list-incidents
---
Lists all incidents in the collection.
##### Base Command

`mongodb-list-incidents`
##### Input

There are no input arguments for this command.

##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-list-incidents```

##### Human Readable Output
### List of incidents in collecion generic
|Incidents|
|---|
| 2468 |
| 1234 |
| 014f5f87-a1bf-4eac-8d36-2ec3b69693ef |
| 6e1807d3-b0ae-40a0-8e82-dad33539c587 |
