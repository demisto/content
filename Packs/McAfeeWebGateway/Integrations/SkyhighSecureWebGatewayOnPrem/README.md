Manages the block and allow lists within Skyhigh Secure Web Gateway.
This integration was integrated and tested with version 11.2.9 of Skyhigh Secure Web Gateway (On Prem)

## Configure Skyhigh Secure Web Gateway (On Prem) in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://192.168.100.55:4712) | True |
| Password | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### swg-get-available-lists

***
Get all available lists.

#### Base Command

`swg-get-available-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Filter to be applied on a list name. | Optional |
| type | Filter to be applied on a list type. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SWG.List.ID | Unknown | List ID. |
| SWG.List.Title | Unknown | List title. | 
| SWG.List.Type | Unknown | List type. | 

#### Command example
```!swg-get-available-lists name=blocklist```
#### Context Example
```json
{
    "SWG": {
        "List": {
            "ID": "com.scur.type.regex.386",
            "Title": "blocklist",
            "Type": "regex"
        }
    }
}
```

#### Human Readable Output

>### Lists
>|Title|ID|Type|
>|---|---|---|
>| blocklist | com.scur.type.regex.386 | regex |
>| Category Blocklist | 5145 | category |
>| Upload Media Type Blocklist | 5146 | mediatype |


### swg-get-list

***
Retrieve a specific list.

#### Base Command

`swg-get-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SWG.List.ListEntries.ListID | Unknown | List ID of the entry's list. |
| SWG.List.ListEntries.Name | Unknown | Entry name. | 
| SWG.List.ListEntries.Description | Unknown | Entry description. | 
| SWG.List.ListEntries.Position | Unknown | Entry position in list. | 
| SWG.List.ID | Unknown | List ID. | 
| SWG.List.Title | Unknown | List title. | 
| SWG.List.Type | Unknown | List Type | 
| SWG.List.Description | Unknown | List description. | 

#### Command example
```!swg-get-list list_id=com.scur.type.regex.386```
#### Context Example
```json
{
    "SWG": {
        "List": {
            "Description": "blocklist",
            "ID": "com.scur.type.regex.386",
            "Title": "blocklist",
            "Type": "regex",
            "ListEntries": [
                {
                    "Description": "this is really evil",
                    "ListID": "com.scur.type.regex.386",
                    "Name": "http*://test.evil/*",
                    "Position": 0
                },
                {
                    "Description": "this is really evil",
                    "ListID": "com.scur.type.regex.386",
                    "Name": "http*://test-more.evil/*",
                    "Position": 1
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### List Properties
>|Title|ID|Description|Type|
>|---|---|---|---|
>| blocklist | com.scur.type.regex.386 | blocklist | regex |
>### blocklist
>|Position|Name|Description|
>|---|---|---|
>| 0 | http*://test.evil/* | this is really evil |
>| 1 | http*://test-more.evil/* | this is really evil |

### swg-get-list-entry

***
Retrieve a specific entry from a list.

#### Base Command

`swg-get-list-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Required | 
| entry_pos | Entry position in the table. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SWG.List.ID | Unknown | List ID of the entry's list. | 
| SWG.List.ListEntries.ListID | Unknown | List ID of the entry's list. | 
| SWG.List.ListEntries.Name | Unknown | Entry name. | 
| SWG.List.ListEntries.Position | Unknown | Entry position in the list. | 
| SWG.List.ListEntries.Description | Unknown | Entry description. | 

#### Command example
```!swg-get-list-entry list_id=com.scur.type.regex.386 entry_pos=0```
#### Context Example
```json
{
    "SWG": {
        "List": {
            "ID": "com.scur.type.regex.386",
            "ListEntries": {
                "Description": "this is really evil",
                "ListID": "com.scur.type.regex.386",
                "Name": "http*://test.evil/*",
                "Position": "0"
            }
        }
    }
}
```

#### Human Readable Output

>### List entry at position 0
>|ListID|Position|Name|Description|
>|---|---|---|---|
>| com.scur.type.regex.386 | 0 | http*://test.evil/* | this is really evil |

### swg-insert-entry

***
Insert a new entry to a list.

#### Base Command

`swg-insert-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Required | 
| entry_pos | Entry position in the table. | Required | 
| description | Entry description. | Optional | 
| name | Entry name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SWG.List.ID | Unknown | List ID of the entry's list. | 
| SWG.List.ListEntries.ListID | Unknown | List ID of the entry's list. | 
| SWG.List.ListEntries.Name | Unknown | Entry name. | 
| SWG.List.ListEntries.Position | Unknown | Entry position in the list. | 
| SWG.List.ListEntries.Description | Unknown | Entry description. | 

#### Command example
```!swg-insert-entry list_id=com.scur.type.regex.386 entry_pos=0 name="http*://evil.corp/*" description="ticket #1: This is an evil domain"```
#### Context Example
```json
{
    "SWG": {
        "List": {
            "ID": "com.scur.type.regex.386",
            "ListEntries": {
                "Description": "ticket #1: This is an evil domain",
                "ListID": "com.scur.type.regex.386",
                "Name": "http*://evil.corp/*",
                "Position": "0"
            }
        }
    }
}
```

#### Human Readable Output

>### Added List entry at position 0
>|ListID|Position|Name|Description|
>|---|---|---|---|
>| com.scur.type.regex.386 | 0 | http*://evil.corp/* | ticket #1: This is an evil domain |


### swg-delete-entry

***
Insert a new entry to a list.

#### Base Command

`swg-delete-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Required | 
| entry_pos | Entry position in the table. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!swg-delete-entry list_id=com.scur.type.regex.386 entry_pos=0```
#### Human Readable Output

>### Deleted List entry at position 0
>|ListID|Position|Name|Description|
>|---|---|---|---|
>| com.scur.type.regex.386 | 0 | http*://evil.corp* | ticket #1: This is an evil domain |


### swg-modify-list

***
Overwrites the complete XML configuration of a list.

#### Base Command

`swg-modify-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Required | 
| config | XML configuration to write to the list. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SWG.List.ListEntries.ListID | Unknown | List ID of the entry's list. |
| SWG.List.ListEntries.Name | Unknown | Entry name. | 
| SWG.List.ListEntries.Description | Unknown | Entry description. | 
| SWG.List.ListEntries.Position | Unknown | Entry position in list. | 
| SWG.List.ID | Unknown | List ID. | 
| SWG.List.Title | Unknown | List title. |
| SWG.List.Type | Unknown | List type. | 
| SWG.List.Description | Unknown | List description. | 

#### Command example
```!swg-modify-list list_id=com.scur.type.regex.386 config=`<list version="1.0.3.46" mwg-version="11.2.9-44482" name="blocklist" id="com.scur.type.regex.386" typeId="com.scur.type.regex" classifier="Other" systemList="false" structuralList="false" defaultRights="2"><description>blocklist</description><content><listEntry><entry>http*://evil.corp/*</entry><description>ticket #1: This is an evil domain</description></listEntry></content></list>` ```
#### Context Example
```json
{
    "SWG": {
        "List": {
            "Description": "blocklist",
            "ID": "com.scur.type.regex.386",
            "Title": "blocklist",
            "Type": "regex",
            "ListEntries": [
                {
                    "Description": "ticket #1: This is an evil domain",
                    "ListID": "com.scur.type.regex.386",
                    "Name": "http*://evil.corp/*",
                    "Position": 0
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Modified blocklist
>|Title|ID|Description|Type|
>|---|---|---|---|
>| blocklist | com.scur.type.regex.386 | blocklist | regex |


### swg-create-list

***
Create a new list.

#### Base Command

`swg-create-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name for the list to be created. | Required | 
| type | Type for the list to be created. Possible values are: category, ip, iprange, mediatype, number, regex, string. Default is string. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SWG.List.ID | Unknown | List ID. | 
| SWG.List.Title | Unknown | List title. |  
| SWG.List.Type | Unknown | List type. |
| SWG.List.Description | Unknown | List description. |  

#### Command example
```!swg-create-list name="blocklist" type=regex```
#### Context Example
```json
{
    "SWG": {
        "List": {
            "Description": "",
            "ID": "com.scur.type.regex.460",
            "Title": "blocklist",
            "Type": "regex"
        }
    }
}
```

#### Human Readable Output

>### Created List Properties
>|Title|ID|Description|Type|
>|---|---|---|---|
>| blocklist | com.scur.type.regex.460 |  | regex |


### swg-delete-list

***
Delete a list.

#### Base Command

`swg-delete-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | List ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!swg-delete-list list_id=com.scur.type.regex.460```
#### Human Readable Output

>### Deleted List Properties
>|Title|ID|Description|Type|
>|---|---|---|---|
>| blocklist | com.scur.type.regex.460 |  | regex |