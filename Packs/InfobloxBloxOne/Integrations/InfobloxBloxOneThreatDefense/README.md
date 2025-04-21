BloxOne Threat Defense is a hybrid cybersecurity solution that leverages DNS as the first line of defense to detect and block cyber threats.

## Configure Infoblox BloxOne Threat Defense in Cortex


| **Parameter**                      | **Required** |
| ---------------------------------- | ------------ |
| Service API Key                    | True         |
| Trust any certificate (not secure) | False        |
| Use system proxy settings          | False        |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### bloxone-td-dossier-lookup-get

***
The Dossier Lookup API returns detailed information on the specified indicator from the requested sources.

#### Base Command

`bloxone-td-dossier-lookup-get`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                                                               | **Required** |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| indicator_type      | The type of indcator to search by. Possible values are: host, ip, url, hash, email.                                                                                                                                           | Required     |
| value               | The indicator to search on.                                                                                                                                                                                                   | Required     |
| sources             | The sources to query. Multiple sources can be specified. If no source is specified, the call will search on all available sources. (You can see the list of the available sources by running bloxone-td-dossier-source-list). | Optional     |
| interval_in_seconds | The interval in seconds between each poll. Default is 10.                                                                                                                                                                     | Optional     |
| timeout             | The timeout in seconds until polling ends. Default is 600.                                                                                                                                                                    | Optional     |
| job_id              | used for polling.                                                                                                                                                                                                             | Optional     |

#### Context Output

| **Path**                        | **Type** | **Description**         |
| ------------------------------- | -------- | ----------------------- |
| BloxOneTD.DossierLookup.source  | String   | The Dossier source.     |
| BloxOneTD.DossierLookup.target  | String   | The targeted indicator. |
| BloxOneTD.DossierLookup.task_id | String   | The Dossier task ID.    |
| BloxOneTD.DossierLookup.type    | String   | The indicator type.     |

#### Command example
```!bloxone-td-dossier-lookup-get indicator_type="ip" value="11.22.33.44" sources="activity,threatfox,ccb"```
#### Context Example
```json
{
    "BloxOneTD": {
        "DossierLookup": [
            {
                "params": {
                    "source": "ccb",
                    "target": "11.22.33.44",
                    "type": "ip"
                },
                "status": "success",
                "task_id": "97bdeca2-b66d-47b1-b1ef-9e4833654df2",
                "time": 6401,
                "v": "3.0.0"
            },
            {
                "data": {
                    "impacted_devices": [],
                    "requests_by_day": []
                },
                "params": {
                    "source": "activity",
                    "target": "11.22.33.44",
                    "type": "ip"
                },
                "status": "success",
                "task_id": "4074cb34-2bec-485d-8d6d-9e9cc88d5229",
                "time": 1708,
                "v": "3.0.0"
            },
            {
                "data": {
                    "matches": []
                },
                "params": {
                    "source": "threatfox",
                    "target": "11.22.33.44",
                    "type": "ip"
                },
                "status": "success",
                "task_id": "73892ea3-1e22-433f-bc74-f59133b914d0",
                "time": 8,
                "v": "3.0.0"
            }
        ]
    }
}
```

#### Human Readable Output

>### Lookalike Domain List
>|Task Id|Type|Target|Source|
>|---|---|---|---|
>| d418b8d6-831c-4f6f-a31a-6d48995d2267 | ip | 11.22.33.44 | threatfox |
>| 91945be3-0cef-4d03-afd7-e4f25864553d | ip | 11.22.33.44 | ccb |
>| 7145a1ca-40a9-43df-b0a3-c4281e5abd7e | ip | 11.22.33.44 | activity |


### bloxone-td-dossier-source-list

***
Get available Dossier sources.

#### Base Command

`bloxone-td-dossier-source-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path**                | **Type** | **Description**            |
| ----------------------- | -------- | -------------------------- |
| BloxOneTD.DossierSource | String   | Available Dossier sources. |

#### Command example
```!bloxone-td-dossier-source-list```
#### Context Example
```json
{
    "BloxOneTD": {
        "DossierSource": [
            "ccb",
            "activity",
            "geo",
            "threatfox"
        ]
    }
}
```

#### Human Readable Output

>### Results
>|DossierSource|
>|---|
>| activity |
>| ccb |
>| geo |
>| threatfox |


### bloxone-td-lookalike-domain-list

***
Get lookalike domain lists.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`bloxone-td-lookalike-domain-list`

#### Input

| **Argument Name** | **Description**                                                                                                                                                  | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| filter            | The free query filter argument.                                                                                                                                  | Optional     |
| target_domain     | Filter by target domain.                                                                                                                                         | Optional     |
| detected_at       | Filter by values that are greater than or equal to the given value. You can use ISO format (e.g. '2023-02-14T00:11:22Z') or use a relative time (e.g. "3 days"). | Optional     |
| limit             | Maximum number of results to return from the query. Default is 50.                                                                                               | Optional     |
| offset            | Return results starting at this offset. Should be an integer. Default is 0.                                                                                      | Optional     |

#### Context Output

| **Path**                                   | **Type** | **Description**                                       |
| ------------------------------------------ | -------- | ----------------------------------------------------- |
| BloxOneTD.LookalikeDomain.detected_at      | Date     | The date of the lookalike detection.                  |
| BloxOneTD.LookalikeDomain.lookalike_domain | String   | The lookalike domain.                                 |
| BloxOneTD.LookalikeDomain.lookalike_host   | String   | The lookalike host.                                   |
| BloxOneTD.LookalikeDomain.reason           | String   | The reason for the detection.                         |
| BloxOneTD.LookalikeDomain.target_domain    | String   | The domain that was targeted by the lookalike domain. |

#### Command example
```!bloxone-td-lookalike-domain-list detected_at="1y"```
#### Context Example
```json
{
    "BloxOneTD": {
        "LookalikeDomain": [
            {
                "detected_at": "2023-01-27T18:43:01Z",
                "lookalike_domain": "test.a.com",
                "lookalike_host": "test.a.com",
                "reason": "Domain is a lookalike to test.com. The creation date is 2023-01-22.",
                "target_domain": "test.com"
            },
            {
                "detected_at": "2023-01-28T18:36:27Z",
                "lookalike_domain": "test.b.com",
                "lookalike_host": "test.b.com",
                "reason": "Domain is a lookalike to test.com and has suspicious registration, behavior, or associations with known threats. The creation date is 2022-11-30.",
                "suspicious": true,
                "target_domain": "test.com"
            },
            {
                "detected_at": "2023-01-28T18:37:03Z",
                "lookalike_domain": "test.c.com",
                "lookalike_host": "test.c.com",
                "reason": "Domain is a lookalike to test.com. The creation date is 2022-09-18.",
                "target_domain": "test.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Detected At|Lookalike Domain|Lookalike Host|Reason|Target Domain|
>|---|---|---|---|---|
>| 2023-01-27T18:43:01Z | test.a.com | test.a.com | Domain is a lookalike to test.com. The creation date is 2023-01-22. | test.com |
>| 2023-01-28T18:36:27Z | test.b.com | test.b.com | Domain is a lookalike to test.com and has suspicious registration, behavior, or associations with known threats. The creation date is 2022-11-30. | test.com |
>| 2023-01-28T18:37:03Z | test.c.com | test.c.com | Domain is a lookalike to test.com. The creation date is 2022-09-18. | test.com |