Checks an XSOAR hosted EDL to make sure it's returning a valid response. Supports PAN-OS (text), CSV, or JSON EDLs.

This integration was integrated and tested with version 6.12 and 8.4 of Cortex XSOAR, and version 3.2.12 of the Generic Export Indicator Service.

## Configure XSOAR EDL Checker in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| EDL Name | The name of the edl from the generic indicator export service | True |
| Username |  | False |
| Password |  | False |
| Trust any certificate (not secure) |  | False |
| XSOAR Version | The version of XSOAR you are using 6.x or 8.x  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xsoaredlchecker-get-edl

***
Checks the EDL and returns the response. 

#### Base Command

`xsoaredlchecker-get-edl`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EDLChecker.Name | unknown | The Name of the EDL from the Generic Indicators Export Service instance | 
| EDLChecker.Status | unknown | The HTTP Status Code returned by the EDL | 
| EDLChecker.Response | unknown | The Response or Error from the check. | 
| EDLChecker.ItemsOnList | unknown | The number of indicators on the list, assuming a successful response\! | 

#### Command example
```!xsoaredlchecker-get-edl```
#### Context Example
```json
{
    "EDLChecker": [
        {
            "ItemsOnList": 2,
            "Name": "domains",
            "Response": "domains returned a 200 response, all should be well",
            "Status": 200
        },
        {
            "ItemsOnList": 0,
            "Name": "ips",
            "Response": "Instance 'ips' is disabled (922)",
            "Status": 400
        }
    ]
}
```

#### Human Readable Output

>### EDL Response for domains
>|Name|Status|Response|ItemsOnList|
>|---|---|---|---|
>| domains | 200 | domains returned a 200 response, all should be well | 2 |
