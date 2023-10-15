Use this script to get RAW log.
Each RSA NetWitness log contains the eventsource meta that contains an IP address that can be requested using RSA NetWitness Packets and Logs.
This log is after set in the field rsarawlogslist.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | field-change-triggered |

## Dependencies

---
This script uses the following commands and scripts.

* netwitness-query
* RSA NetWitness Packets and Logs
* netwitness-packets

## Used In

---
This script is used in the following playbooks and scripts.

* rsaalerts

## Inputs

---
There are no inputs for this script.

## Outputs

---
There are no outputs for this script.


## Script Examples

### Example command

```!RSA_GetRawLog```

### Context Example

```json
 {
    "RSA Alerts": [
        {
            "created": "2023-07-03T11:04:16.408Z",
            "detail": null,
            "events": [
                {
                    "destination": {},
                    "eventSource": "1.1.1.1:56005",
                    "eventSourceId": "12123434",
                    "source": {}
                }
            ],
            "id": "123456789",
            "riskScore": "50",
            "source": "NetWitness Investigate",
            "title": "Incident name",
            "type": "Log",
        },
    ]
}
```
