Returns a list of all the users marked as away in Cortex XSOAR

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---
There are no inputs for this script.

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AwayUsers.id | Away user ID. | String |
| AwayUsers.username | Away user username. | String |
| AwayUsers.name | Away user name. | String |
| AwayUsers.phone | Away user phone. | String |
| AwayUsers.roles | Away user roles. | Unknown |
| AwayUsers.email | Away user email. | Unknown |


## Script Example
```!GetAwayUsers```

## Context Example
```json
{
    "CortexXSOAR": {
        "AwayUsers": {
            "email": "admintest@demisto.com",
            "id": "admin",
            "name": "Admin Dude",
            "phone": "+650-123456",
            "roles": {
                "demisto": [
                    "Administrator"
                ]
            },
            "username": "admin"
        }
    }
}
```

## Human Readable Output

>### Away Users
>|Email|Id|Name|Phone|Roles|Username|
>|---|---|---|---|---|---|
>| admintest@demisto.com | admin | Admin Dude | +650-123456 | demisto: Administrator | admin |

