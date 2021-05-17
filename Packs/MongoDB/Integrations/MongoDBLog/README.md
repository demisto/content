## Overview
---

Writes log data to a MongoDB collection.
This integration was integrated and tested with version v4.2.3 of MongoDB.

The account user must have appropriate permissions -  ***root*** role to execute the API calls.

## Use Cases
---

1. Write to MongoDB Log collection.
2. Read from MongoDB log collection.
3. Get the number of log entries.

## Configure MongoDB Log on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for MongoDB Log.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __MongoDB Username__
    * __URI (mongodb://IP/FQDN:Port Number)__
    * __Database Name__
    * __Collection Name__
    * __Trust any certificate (not secure)__
    * __Use SSL/TLS secured connection__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. mongodb-read-log
2. mongodb-write-log
3. mongodb-logs-number
### 1. mongodb-read-log
---
Returns all log entries.
##### Base Command

`mongodb-read-log`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of logs to return. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-read-log limit=5```


##### Human Readable Output
### The log documents/records for collection "log"
|log|
|---|
| {'name': 'Midhuna', 'age': 23, 'cars': ['BMW 320d', 'Audi R8'], 'place': 'Amaravati'},{'timestamp': '2020-03-22T18:57:33+00:00', 'entity': 'test', 'playbook': 'my playbook', 'action': 'create', 'analyst': 'admin'},{'test': 'value'},{'123': {'modified': '2020-03-22T19:14:29+00:00', 'key': 'test', 'value': '123'}},{'timestamp': '2020-03-23T10:45:39+00:00', 'entity': '{test: demisto}', 'playbook': 'mongodb', 'action': 'create', 'analyst': 'admin'} |


### 2. mongodb-write-log
---
Adds a log entry.
##### Base Command

`mongodb-write-log`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| playbook | The playbook that was used. | Optional | 
| user | The assigned user. | Optional | 
| id | Entity to write to the log. | Optional | 
| action | The actions that were performed. | Optional | 
| message | Message for the entry. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MongoDB.Entry.Action | String | The actions that were performed. | 
| MongoDB.Entry.User | String | Assigned analyst. | 
| MongoDB.Entry.ID | String | Entity to write to the log. | 
| MongoDB.Entry.EntryID | String | Entry ID. | 
| MongoDB.Entry.Playbook | String | The playbook that was used. | 
| MongoDB.Entry.Timestamp | Date | Entry timestamp. | 
| MongoDB.Entry.Message | String | The message of the entry. | 


##### Command Example
```!mongodb-write-log action=create message="This is a test message"```

##### Context Example
```
{
    "MongoDB.Entry": {
        "Timestamp": "2020-04-12T07:59:43+00:00", 
        "EntryID": "5e92ca6f8f55e45510637880", 
        "Playbook": null, 
        "Action": "create", 
        "Message": "This is a test message", 
        "ID": "6e1807d3-b0ae-40a0-8e82-dad33539c587", 
        "User": null
    }
}
```

##### Human Readable Output
MongoDB Log - 1 document/record added

### 3. mongodb-logs-number
---
Returns the number of log entries.
##### Base Command

`mongodb-logs-number`
##### Input

There are no input arguments for this command.

##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-logs-number```

##### Human Readable Output
The count of log documents/records is 56
