Pack helps to integrate Group-IB Digital Risk Protection and get violations incidents directly into Cortex XSOAR.
This integration was integrated and tested with version 1.0 of Group-IB Digital Risk Protection.

## Configure Group-IB Digital Risk Protection in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| GIB DRP URL |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incidents Fetch Interval |  | False |
| Username |  | True |
| Password |  | True |
| Violation Section to filter the received Violation |  | False |
| Brands to filter the received Violation | Brands for filtering received violations. The list of available brands can be obtained with the command \!gibdrp-get-brands in the menu WarRoom -&gt; Playground. After getting the brands you must specify the brand ID for which you want to receive violations. Attention\! Currently filtering is available only by one brand in one Instance | False |
| Incidents first fetch | Date to start fetching incidents from. | False |
| Download images | Enables or disables loading of each image in each violation. Can significantly affect the speed of data collection if the parameter is enabled, i.e. set to True | False |
| Getting Typosquatting only | Allows for the collection of offenses suitable only for Typo Squatting | False |
| Number of requests per collection | A number of requests per collection that integration sends in one fetch iteration \(each request picks up to 30 incidents\). If you face some runtime errors, lower the value. | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gibdrp-get-brands

***
Receive all configured brands.

#### Base Command

`gibdrp-get-brands`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.OtherInfo | string | List of configured brands. | 

#### Command example
```!gibdrp-get-brands```
#### Context Example
```json
{
    "GIBDRP": {
        "OtherInfo": {
            "brands": [
                {
                    "id": "PvY1BZUBSFbLZGo2x8TA",
                    "name": "Example Brand"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Installed Brands
>|Name|Id|
>|---|---|
>| Example Brand | PvY1BZUBSFbLZGo2x8TA |


### gibdrp-get-subscriptions

***
Receive all configured subscriptions.

#### Base Command

`gibdrp-get-subscriptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.OtherInfo | string | List of configured subscriptions. | 

#### Command example
```!gibdrp-get-subscriptions```
#### Context Example
```json
{
    "GIBDRP": {
        "OtherInfo": {
            "subscriptions": [
                "scam"
            ]
        }
    }
}
```

#### Human Readable Output

>### Purchased subscriptions
>|Subscriptions|
>|---|
>| scam |


### gibdrp-get-violation-by-id

***
Getting a single violation by its ID.

#### Base Command

`gibdrp-get-violation-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID violation. | Required | 

#### Context Output

There is no context output for this command.
### gibdrp-change-violation-status

***
Changing the status of a single violation.

#### Base Command

`gibdrp-change-violation-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID violation. | Required | 
| status | What status to change to. Possible values are: approve, reject. | Required | 

#### Context Output

There is no context output for this command.
