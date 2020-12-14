Match IP address in all the CIDRs indicators (longest match)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| ip | IP Address to match |
| tags | Tags to search \(comma separated\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MatchingCIDRIndicator | Matching CIDR Indicator | Unknown |


## Script Example
```!MatchIPinCIDRIndicators ip="44.224.1.1" tags="AWS,GCP,Azure"```

## Context Example
```json
{
    "MatchingCIDRIndicator": {
        "CustomFields": {
            "region": "us-west-2",
            "service": "EC2",
            "tags": [
                "AWS",
                "AMAZON",
                "EC2"
            ]
        },
        "expiration": "2020-11-30T22:46:50.594897749Z",
        "expirationStatus": "active",
        "firstSeen": "2020-11-23T22:04:13.912289994Z",
        "id": "70575",
        "lastSeen": "2020-11-23T22:15:06.02640521Z",
        "score": 1,
        "sourceBrands": [
            "AWS Feed"
        ],
        "sourceInstances": [
            "AWS Feed_instance_1"
        ],
        "value": "44.224.0.0/11"
    }
}
```

## Human Readable Output

>### Results
>|CustomFields|expiration|expirationStatus|firstSeen|id|lastSeen|score|sourceBrands|sourceInstances|value|
>|---|---|---|---|---|---|---|---|---|---|
>| region: us-west-2<br/>service: EC2<br/>tags: AWS,<br/>AMAZON,<br/>EC2 | 2020-11-30T22:46:50.594897749Z | active | 2020-11-23T22:04:13.912289994Z | 70575 | 2020-11-23T22:15:06.02640521Z | 1 | AWS Feed | AWS Feed_instance_1 | 44.224.0.0/11 |

