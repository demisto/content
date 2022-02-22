Enhancement automation for type indicator, to enrich the value from Cofense Triage.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | enhancement |
| Version | 6.0.0 |

## Dependencies
This script uses the following commands and scripts.
* cofense-threat-indicator-list

## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| threat_value | Value to look up - Supports Email, Domain, URL, Hash, Hostname, SHA1, SHA256, MD5. |

## Outputs
There are no outputs for this script.


## Script Example
```!CofenseTriageThreatEnrichmentScript threat_value=12345a7965b72b5a02247dc580b6a75280ef8309ef58dcdc14152234d2123457```

## Context Example
```json
{
    "Cofense": {
        "ThreatIndicator": [
            {
                "attributes": {
                    "created_at": "2020-10-26T10:47:09.675Z",
                    "threat_level": "Malicious",
                    "threat_source": "Triage-UI",
                    "threat_type": "SHA256",
                    "threat_value": "12345a7965b72b5a02247dc580b6a75280ef8309ef58dcdc14152234d2123457",
                    "updated_at": "2021-03-15T11:23:17.453Z"
                },
                "id": "1",
                "links": {
                    "self": "https://triage.example.com/api/public/v2/threat_indicators/1"
                },
                "relationships": {
                    "comments": {
                        "links": {
                            "related": "https://triage.example.com/api/public/v2/threat_indicators/1/comments",
                            "self": "https://triage.example.com/api/public/v2/threat_indicators/1/relationships/comments"
                        }
                    },
                    "owner": {
                        "data": {
                            "id": "5",
                            "type": "api_applications"
                        },
                        "links": {
                            "related": "https://triage.example.com/api/public/v2/threat_indicators/1/owner",
                            "self": "https://triage.example.com/api/public/v2/threat_indicators/1/relationships/owner"
                        }
                    },
                    "reports": {
                        "links": {
                            "related": "https://triage.example.com/api/public/v2/threat_indicators/1/reports",
                            "self": "https://triage.example.com/api/public/v2/threat_indicators/1/relationships/reports"
                        }
                    }
                },
                "type": "threat_indicators"
            },
            {
                "attributes": {
                    "created_at": "2021-06-11T06:39:47.376Z",
                    "threat_level": "Malicious",
                    "threat_source": "XSOAR-UI",
                    "threat_type": "SHA256",
                    "threat_value": "12345a7965b72b5a02247dc580b6a75280ef8309ef58dcdc14152234d2123457",
                    "updated_at": "2021-06-11T06:39:47.382Z"
                },
                "id": "325",
                "links": {
                    "self": "https://triage.example.com/api/public/v2/threat_indicators/325"
                },
                "relationships": {
                    "comments": {
                        "links": {
                            "related": "https://triage.example.com/api/public/v2/threat_indicators/325/comments",
                            "self": "https://triage.example.com/api/public/v2/threat_indicators/325/relationships/comments"
                        }
                    },
                    "owner": {
                        "data": {
                            "id": "3",
                            "type": "api_applications"
                        },
                        "links": {
                            "related": "https://triage.example.com/api/public/v2/threat_indicators/325/owner",
                            "self": "https://triage.example.com/api/public/v2/threat_indicators/325/relationships/owner"
                        }
                    },
                    "reports": {
                        "links": {
                            "related": "https://triage.example.com/api/public/v2/threat_indicators/325/reports",
                            "self": "https://triage.example.com/api/public/v2/threat_indicators/325/relationships/reports"
                        }
                    }
                },
                "type": "threat_indicators"
            }
        ]
    }
}
```

## Human Readable Output

>### Threat Indicator(s)
>|Threat Indicator ID|Threat Level|Threat Type|Threat Value|Threat Source|Created At|Updated At|
>|---|---|---|---|---|---|---|
>| 1 | Malicious | SHA256 | 12345a7965b72b5a02247dc580b6a75280ef8309ef58dcdc14152234d2123457 | Triage-UI | 2020-10-26T10:47:09.675Z | 2021-03-15T11:23:17.453Z |
>| 325 | Malicious | SHA256 | 12345a7965b72b5a02247dc580b6a75280ef8309ef58dcdc14152234d2123457 | XSOAR-UI | 2021-06-11T06:39:47.376Z | 2021-06-11T06:39:47.382Z |
