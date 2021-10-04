Enhancement script to enrich PassiveTotal host pair of parents for Domain and IP type of indicators.
It can be set by following these steps:
 - Settings > ADVANCED > Indicator Type
 - Edit Domain and IP Indicator one by one 
 - Add this script into Enhancement Scripts
 
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | enhancement |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* pt-get-host-pairs

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_value | Domain or IP indicator value that need to enrich |

## Outputs
---
There are no outputs for this script.

## Script Example
```!RiskIQPassiveTotalHostPairChildrenScript indicator_value=ns1.furth.com.ar```

## Context Example
```
{
    "PassiveTotal": {
        "HostPair": [
            {
                "cause": "redirect",
                "child": "furth.com.ar",
                "firstSeen": "2020-05-29 07:05:22",
                "lastSeen": "2020-06-10 11:53:23",
                "parent": "ns1.furth.com.ar"
            },
            {
                "cause": "parentPage",
                "child": "ns1.furth.com.ar",
                "firstSeen": "2020-05-02 06:47:23",
                "lastSeen": "2020-06-08 03:08:38",
                "parent": "ns1.furth.com.ar"
            }
        ]
    }
}
```

## Human Readable Output

>### Total Retrieved Record(s): 2
>### HOST PAIRS
>|Parent Hostname|Child Hostname|First (GMT)|Last (GMT)|Cause|
>|---|---|---|---|---|
>| ns1.furth.com.ar | furth.com.ar | 2020-05-29 07:05:22 | 2020-06-10 11:53:23 | redirect |
>| ns1.furth.com.ar | ns1.furth.com.ar | 2020-05-02 06:47:23 | 2020-06-08 03:08:38 | parentPage |
