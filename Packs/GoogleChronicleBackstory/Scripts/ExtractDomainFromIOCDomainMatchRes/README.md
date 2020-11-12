Extracts domain and its details from the Chronicle IOC Domain match response.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| json_response | JSON response of IOC Domain Match |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain.Name | The suspicious domain name recently observed in enterprise. | string |
| ChronicleIOCDomainMatches.Domain | The suspicious domain name recently observed in enterprise. | string |
| ChronicleIOCDomainMatches.IOCIngestTime | Time\(UTC\) the IOC was first seen by Chronicle. | date |
| ChronicleIOCDomainMatches.FirstSeen | Time\(UTC\) the artifact was first seen within your enterprise. | date |
| ChronicleIOCDomainMatches.LastSeen | Time\(UTC\) the artifact was most recently seen within your enterprise. | date |


## Script Example
```!ExtractDomainFromIOCDomainMatchRes json_response="{\"Artifact\": \"e9428.b.akamaiedge.net\", \"IocIngestTime\": \"2020-07-17T20:00:00Z\", \"FirstAccessedTime\": \"2018-11-05T12:01:29Z\", \"LastAccessedTime\": \"2018-11-09T11:51:03Z\", \"Sources\": [{\"Category\": \"Observed serving executables\", \"IntRawConfidenceScore\": 0, \"NormalizedConfidenceScore\": \"Low\", \"RawSeverity\": \"Low\", \"Source\": \"ET Intelligence Rep List\"}]}"```

## Context Example
```
{
    "ChronicleIOCDomainMatches": {
        "Domain": "e9428.b.akamaiedge.net",
        "FirstSeen": "2018-11-05T12:01:29Z",
        "IOCIngestTime": "2020-07-17T20:00:00Z",
        "LastSeen": "2018-11-09T11:51:03Z"
    },
    "Domain": {
        "Name": "e9428.b.akamaiedge.net"
    }
}
```

## Human Readable Output
{}
