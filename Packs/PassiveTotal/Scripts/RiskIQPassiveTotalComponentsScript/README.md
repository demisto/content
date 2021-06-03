Enhancement script to enrich PassiveTotal components for Domain and IP type of indicators.
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
* pt-get-components

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_value | Domain or IP indicator value that need to enrich |

## Outputs
---
There are no outputs for this script.

## Script Example
```!RiskIQPassiveTotalComponentsScript indicator_value=www.furth.com.ar```

## Context Example
```
{
    "DBotScore": {
        "Indicator": "www.furth.com.ar",
        "Score": 0,
        "Type": "domain",
        "Vendor": "PassiveTotal"
    },
    "Domain": {
        "Name": "www.furth.com.ar"
    },
    "PassiveTotal": {
        "Component": [
            {
                "category": "Framework",
                "firstSeen": "2020-05-29 10:57:44",
                "hostname": "www.furth.com.ar",
                "label": "PHP",
                "lastSeen": "2020-05-29 10:57:44"
            },
            {
                "category": "Server",
                "firstSeen": "2020-05-29 10:57:44",
                "hostname": "www.furth.com.ar",
                "label": "Apache",
                "lastSeen": "2020-05-29 10:57:44"
            },
            {
                "category": "Server Module",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "mod_bwlimited",
                "lastSeen": "2017-10-24 15:53:52",
                "version": "1.4"
            },
            {
                "category": "Server Module",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "OpenSSL",
                "lastSeen": "2017-10-24 15:53:52",
                "version": "1.0.1e-fips"
            },
            {
                "category": "Server",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "Apache",
                "lastSeen": "2017-10-24 15:53:52",
                "version": "2.2.29"
            },
            {
                "category": "Operating System",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "Unix",
                "lastSeen": "2017-10-24 15:53:52"
            },
            {
                "category": "Server Module",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "mod_ssl",
                "lastSeen": "2017-10-24 15:53:52",
                "version": "2.2.29"
            }
        ]
    }
}
```

## Human Readable Output

>### Total Retrieved Record(s): 7
>### COMPONENTS
>|Hostname|First (GMT)|Last (GMT)|Category|Value|Version|
>|---|---|---|---|---|---|
>| www.furth.com.ar | 2020-05-29 10:57:44 | 2020-05-29 10:57:44 | Framework | PHP |  |
>| www.furth.com.ar | 2020-05-29 10:57:44 | 2020-05-29 10:57:44 | Server | Apache |  |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Server Module | mod_bwlimited | 1.4 |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Server Module | OpenSSL | 1.0.1e-fips |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Server | Apache | 2.2.29 |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Operating System | Unix |  |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Server Module | mod_ssl | 2.2.29 |
