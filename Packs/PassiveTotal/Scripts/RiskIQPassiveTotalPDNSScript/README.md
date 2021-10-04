Enhancement script to enrich PDNS information for Domain and IP type of indicators.
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
* pt-get-pdns-details

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_value | domain or IP indicator value that need to enrich |

## Outputs
---
There are no outputs for this script.

## Script Example
```!RiskIQPassiveTotalPDNSScript indicator_value="www.furth.com.ar"```

## Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "furth.com.ar",
            "Score": 0,
            "Type": "domain",
            "Vendor": "PassiveTotal"
        },
        {
            "Indicator": "77.81.241.5",
            "Score": 0,
            "Type": "ip",
            "Vendor": "PassiveTotal"
        },
        {
            "Indicator": "184.75.255.33",
            "Score": 0,
            "Type": "ip",
            "Vendor": "PassiveTotal"
        }
    ],
    "Domain": {
        "Name": "furth.com.ar"
    },
    "IP": [
        {
            "Address": "77.81.241.5"
        },
        {
            "Address": "184.75.255.33"
        }
    ],
    "PassiveTotal": {
        "PDNS": [
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2010-12-15 09:10:10",
                "lastSeen": "2020-06-17 05:26:33",
                "recordHash": "abf781b2484ea79d521cffb0745b71319d4db1158f71bb019b41077f8e55b035",
                "recordType": "CNAME",
                "resolve": "furth.com.ar",
                "resolveType": "domain",
                "source": [
                    "riskiq",
                    "pingly"
                ],
                "value": "www.furth.com.ar"
            },
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2020-05-29 03:57:44",
                "lastSeen": "2020-06-17 05:26:33",
                "recordHash": "d7183564ca617e173fc26aeff66a38bb5c1b9089e56819851183860b9a37ccca",
                "recordType": "A",
                "resolve": "77.81.241.5",
                "resolveType": "ip",
                "source": [
                    "riskiq",
                    "pingly"
                ],
                "value": "www.furth.com.ar"
            },
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2016-01-11 15:45:15",
                "lastSeen": "2017-10-24 08:53:52",
                "recordHash": "345780dcde96f0c28e3b93ec53bd33067f26075f30c2d4e49fafe0d2396194ca",
                "recordType": "A",
                "resolve": "184.75.255.33",
                "resolveType": "ip",
                "source": [
                    "riskiq"
                ],
                "value": "www.furth.com.ar"
            },
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2020-06-17 05:26:33",
                "lastSeen": "2020-06-17 05:26:33",
                "recordHash": "63deb7c38cbea98f631777fd3ba89de0c270178bd37eb6a270ee7e37b3cd92e5",
                "recordType": "SOA",
                "resolve": "webmaster@furth.com.ar",
                "resolveType": "email",
                "source": [
                    "pingly"
                ],
                "value": "www.furth.com.ar"
            },
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2020-06-17 05:26:33",
                "lastSeen": "2020-06-17 05:26:33",
                "recordHash": "24fa99da36eecc22b8970a33f8adf0f150598391319df4fc02128d677999e886",
                "recordType": "MX",
                "resolve": "furth.com.ar",
                "resolveType": "domain",
                "source": [
                    "pingly"
                ],
                "value": "www.furth.com.ar"
            }
        ]
    }
}
```

## Human Readable Output

>### Total Retrieved Record(s): 5
>### PDNS detail(s)
>|Resolve|Resolve Type|Record Type|Collected (GMT)|First Seen (GMT)|Last Seen (GMT)|Source|Record Hash|
>|---|---|---|---|---|---|---|---|
>| furth.com.ar | domain | CNAME | 2020-06-17 12:26:33 | 2010-12-15 09:10:10 | 2020-06-17 05:26:33 | riskiq, pingly | abf781b2484ea79d521cffb0745b71319d4db1158f71bb019b41077f8e55b035 |
>| 77.81.241.5 | ip | A | 2020-06-17 12:26:33 | 2020-05-29 03:57:44 | 2020-06-17 05:26:33 | riskiq, pingly | d7183564ca617e173fc26aeff66a38bb5c1b9089e56819851183860b9a37ccca |
>| 184.75.255.33 | ip | A | 2020-06-17 12:26:33 | 2016-01-11 15:45:15 | 2017-10-24 08:53:52 | riskiq | 345780dcde96f0c28e3b93ec53bd33067f26075f30c2d4e49fafe0d2396194ca |
>| webmaster@furth.com.ar | email | SOA | 2020-06-17 12:26:33 | 2020-06-17 05:26:33 | 2020-06-17 05:26:33 | pingly | 63deb7c38cbea98f631777fd3ba89de0c270178bd37eb6a270ee7e37b3cd92e5 |
>| furth.com.ar | domain | MX | 2020-06-17 12:26:33 | 2020-06-17 05:26:33 | 2020-06-17 05:26:33 | pingly | 24fa99da36eecc22b8970a33f8adf0f150598391319df4fc02128d677999e886 |
