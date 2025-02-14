Integration to pull assets and other ASM related information.
This integration was integrated and tested with version 2.0 of Cortex Expander.

## Configure Cortex Xpanse in Cortex


| **Parameter**                                                                    | **Description**                                                                                                                                                                                                                                         | **Required** |
|----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Server URL                                                                       | The web UI with \`api-\` appended to front \(e.g., <https://api-xsiam.paloaltonetworks.com\>). For more information, see <https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis>. | True         |
| API Key ID                                                                       | For more information, see <https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis>.                                                                                                | True         |
| API Key                                                                          | **Only standard API key type is supported**.                                                                                                                                                                                                            | True         |
| Trust any certificate (not secure)                                               |                                                                                                                                                                                                                                                         | False        |
| Use system proxy settings                                                        |                                                                                                                                                                                                                                                         | False        |
| Fetch incidents                                                                  |                                                                                                                                                                                                                                                         | False        |
| Incidents Fetch Interval                                                         |                                                                                                                                                                                                                                                         | False        |
| Incident type                                                                    |                                                                                                                                                                                                                                                         | False        |
| Maximum number of alerts per fetch                                               | The maximum number of alerts per fetch. Cannot exceed 100.                                                                                                                                                                                              | False        |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |                                                                                                                                                                                                                                                         | False        |
| Alert Severities to Fetch                                                        | The severity of the alerts that will be fetched. If no severity is provided then alerts of all the severities will be fetched. Note: An alert whose status was changed to a filtered status after its creation time will not be fetched.                | False        |
| Source Reliability                                                               | Reliability of the source providing the intelligence data. Used for !ip and !domain commands.                                                                                                                                                           | False        |
| Look Back (Minutes to look back when fetching) | Use this parameter to determine how far back in time to look in the search for incidents that were created before the last run time and did not match the query when they were created. | False        |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### asm-list-external-service

***
Get a list of all your external services filtered by business units, externally detected providers, domain, externally inferred CVEs, active classifications, inactive classifications, service name, service type, protocol, IP address, is active, and discovery type. Maximum result limit is 100 assets.

#### Base Command

`asm-list-external-service`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address on which to search. | Optional | 
| domain | Domain on which to search. | Optional | 
| is_active | Whether the service is active. Possible values are: yes, no. | Optional | 
| discovery_type | How service was discovered. Possible values are: colocated_on_ip, directly_discovery, unknown. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.ExternalService.service_id | String | External service UUID. | 
| ASM.ExternalService.service_name | String | Name of the external service. | 
| ASM.ExternalService.service_type | String | Type of the external service. | 
| ASM.ExternalService.ip_address | String | IP address of the external service. | 
| ASM.ExternalService.externally_detected_providers | String | Providers of external service. | 
| ASM.ExternalService.is_active | String | Whether the external service is active. | 
| ASM.ExternalService.first_observed | Date | Date of the first observation of the external service. | 
| ASM.ExternalService.last_observed | Date | Date of the last observation of the external service. | 
| ASM.ExternalService.port | Number | Port number of the external service. | 
| ASM.ExternalService.protocol | String | Protocol number of the external service. | 
| ASM.ExternalService.inactive_classifications | String | External service classifications that are no longer active. | 
| ASM.ExternalService.discovery_type | String | How the external service was discovered. | 
| ASM.ExternalService.business_units | String | External service associated business units. | 
| ASM.ExternalService.externally_inferred_vulnerability_score | Unknown | External service vulnerability score. | 

#### Command example

```!asm-list-external-service domain=acme.com is_active=yes discovery_type=directly_discovery```

#### Context Example

```json
{
    "ASM": {
        "ExternalService": [
            {
                "active_classifications": [
                    "HttpServer",
                    "MicrosoftOWAServer",
                    "ServerSoftware",
                    "MicrosoftIisWebServer",
                    "ApplicationServerSoftware"
                ],
                "business_units": [
                    "Acme",
                    "VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "autodiscover.acme.com"
                ],
                "externally_detected_providers": [
                    "Microsoft Azure"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659395040000,
                "inactive_classifications": [],
                "ip_address": [
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1"
                ],
                "is_active": "Active",
                "last_observed": 1663024320000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "4c755fea-59e8-3719-8829-9f6adde65068",
                "service_name": "HTTP Server at autodiscover.acme.com:80",
                "service_type": "HttpServer"
            },
            {
                "active_classifications": [
                    "HttpServer",
                    "ServerSoftware"
                ],
                "business_units": [
                    "Acme",
                    "VanDelay Industries"
                ],
                "discovery_type": "DirectlyDiscovered",
                "domain": [
                    "web.acme.com"
                ],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "externally_inferred_cves": [],
                "externally_inferred_vulnerability_score": null,
                "first_observed": 1659396480000,
                "inactive_classifications": [],
                "ip_address": [
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1",
                    "1.1.1.1"
                ],
                "is_active": "Active",
                "last_observed": 1663029060000,
                "port": 80,
                "protocol": "TCP",
                "service_id": "32c85ab1-fc98-3061-a813-2fe5daf7e7c5",
                "service_name": "HTTP Server at web.acme.com:80",
                "service_type": "HttpServer"
            }
        ]
    }
}
```

#### Human Readable Output

>### External Services
>
>|Active Classifications|Business Units|Discovery Type|Domain|Externally Detected Providers|First Observed|Ip Address|Is Active|Last Observed|Port|Protocol|Service Id|Service Name|Service Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| HttpServer,<br/>MicrosoftOWAServer,<br/>ServerSoftware,<br/>MicrosoftIisWebServer,<br/>ApplicationServerSoftware | Acme,<br/>VanDelay Industries | DirectlyDiscovered | autodiscover.acme.com | Microsoft Azure | 1659395040000 | 1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1 | Active | 1663024320000 | 80 | TCP | 4c755fea-59e8-3719-8829-9f6adde65068 | HTTP Server at autodiscover.acme.com:80 | HttpServer |
>| HttpServer,<br/>ServerSoftware | Acme,<br/>VanDelay Industries | DirectlyDiscovered | web.acme.com | Amazon Web Services | 1659396480000 | 1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1,<br/>1.1.1.1 | Active | 1663029060000 | 80 | TCP | 32c85ab1-fc98-3061-a813-2fe5daf7e7c5 | HTTP Server at web.acme.com:80 | HttpServer |


### asm-get-external-service

***
Get service details according to the service ID.

#### Base Command

`asm-get-external-service`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | A string representing the service ID you want to get details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.ExternalService.service_id | String | External service UUID. | 
| ASM.ExternalService.service_name | String | Name of the external service. | 
| ASM.ExternalService.service_type | String | Type of the external service. | 
| ASM.ExternalService.ip_address | String | IP address of the external service. | 
| ASM.ExternalService.externally_detected_providers | String | Providers of the external service. | 
| ASM.ExternalService.is_active | String | Whether the external service is active. | 
| ASM.ExternalService.first_observed | Date | Date of the first observation of the external service. | 
| ASM.ExternalService.last_observed | Date | Date of the last observation of the external service. | 
| ASM.ExternalService.port | Number | Port number of the external service. | 
| ASM.ExternalService.protocol | String | Protocol of the external service. | 
| ASM.ExternalService.inactive_classifications | String | External service classifications that are no longer active. | 
| ASM.ExternalService.discovery_type | String | How the external service was discovered. | 
| ASM.ExternalService.business_units | String | External service associated business units. | 
| ASM.ExternalService.externally_inferred_vulnerability_score | Unknown | External service vulnerability score. | 
| ASM.ExternalService.details | String | Additional details. | 

#### Command example

```!asm-get-external-service service_id=94232f8a-f001-3292-aa65-63fa9d981427```

#### Context Example

```json
{
    "ASM": {
        "ExternalService": {
            "active_classifications": [
                "SSHWeakMACAlgorithmsEnabled",
                "SshServer",
                "OpenSSH"
            ],
            "business_units": [
                "Acme"
            ],
            "details": {
                "businessUnits": [
                    {
                        "name": "Acme"
                    }
                ],
                "certificates": [],
                "classifications": [
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774120000,
                        "lastObserved": 1663026480000,
                        "name": "SshServer",
                        "values": [
                            {
                                "firstObserved": 1662774169000,
                                "jsonValue": "{\"version\":\"2.0\",\"serverVersion\":\"OpenSSH_7.6p1\",\"extraInfo\":\"Ubuntu-4ubuntu0.7\"}",
                                "lastObserved": 1663026500000
                            }
                        ]
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774120000,
                        "lastObserved": 1663026480000,
                        "name": "SSHWeakMACAlgorithmsEnabled",
                        "values": [
                            {
                                "firstObserved": 1662774169000,
                                "jsonValue": "{}",
                                "lastObserved": 1663026500000
                            }
                        ]
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774120000,
                        "lastObserved": 1663026480000,
                        "name": "OpenSSH",
                        "values": [
                            {
                                "firstObserved": 1662774169000,
                                "jsonValue": "{\"version\":\"7.6\"}",
                                "lastObserved": 1663026500000
                            }
                        ]
                    }
                ],
                "domains": [],
                "enrichedObservationSource": "CLOUD",
                "inferredCvesObserved": [
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2020-15778",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "HIGH",
                            "cvssScoreV2": 6.8,
                            "cvssScoreV3": 7.8,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2021-41617",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "HIGH",
                            "cvssScoreV2": 4.4,
                            "cvssScoreV3": 7,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2019-6110",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 4,
                            "cvssScoreV3": 6.8,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2019-6109",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 4,
                            "cvssScoreV3": 6.8,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2020-14145",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 4.3,
                            "cvssScoreV3": 5.9,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2019-6111",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 5.8,
                            "cvssScoreV3": 5.9,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2018-20685",
                            "cveSeverityV2": "LOW",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 2.6,
                            "cvssScoreV3": 5.3,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2018-15919",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 5,
                            "cvssScoreV3": 5.3,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2016-20012",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 4.3,
                            "cvssScoreV3": 5.3,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2018-15473",
                            "cveSeverityV2": "MEDIUM",
                            "cveSeverityV3": "MEDIUM",
                            "cvssScoreV2": 5,
                            "cvssScoreV3": 5.3,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    },
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "inferredCve": {
                            "cveId": "CVE-2021-36368",
                            "cveSeverityV2": "LOW",
                            "cveSeverityV3": "LOW",
                            "cvssScoreV2": 2.6,
                            "cvssScoreV3": 3.7,
                            "inferredCveMatchMetadata": {
                                "confidence": "High",
                                "inferredCveMatchType": "ExactVersionMatch",
                                "product": "openssh",
                                "vendor": "openbsd",
                                "version": "7.6"
                            }
                        },
                        "lastObserved": 1663026500000
                    }
                ],
                "ip_ranges": {},
                "ips": [
                    {
                        "activityStatus": "Active",
                        "firstObserved": 1662774169000,
                        "geolocation": {
                            "city": "ASHBURN",
                            "countryCode": "US",
                            "latitude": 39.0438,
                            "longitude": -77.4879,
                            "regionCode": "VA",
                            "timeZone": null
                        },
                        "ip": 873887795,
                        "lastObserved": 1663026500000,
                        "protocol": "TCP",
                        "provider": "AWS"
                    }
                ],
                "providerDetails": [
                    {
                        "firstObserved": 1662774169000,
                        "lastObserved": 1663026500000,
                        "name": "AWS"
                    }
                ],
                "serviceKey": "1.1.1.1:22",
                "serviceKeyType": "IP",
                "tlsVersions": []
            },
            "discovery_type": "ColocatedOnIp",
            "domain": [],
            "externally_detected_providers": [
                "Amazon Web Services"
            ],
            "externally_inferred_cves": [
                "CVE-2020-15778",
                "CVE-2021-41617",
                "CVE-2019-6110",
                "CVE-2019-6109",
                "CVE-2020-14145",
                "CVE-2019-6111",
                "CVE-2018-20685",
                "CVE-2018-15919",
                "CVE-2016-20012",
                "CVE-2018-15473",
                "CVE-2021-36368"
            ],
            "externally_inferred_vulnerability_score": 7.8,
            "first_observed": 1662774120000,
            "inactive_classifications": [],
            "ip_address": [
                "1.1.1.1"
            ],
            "is_active": "Active",
            "last_observed": 1663026480000,
            "port": 22,
            "protocol": "TCP",
            "service_id": "94232f8a-f001-3292-aa65-63fa9d981427",
            "service_name": "SSH Server at 1.1.1.1:22",
            "service_type": "SshServer"
        }
    }
}
```

#### Human Readable Output

>### External Service
>
>|Active Classifications|Business Units|Details|Discovery Type|Externally Detected Providers|Externally Inferred Cves|Externally Inferred Vulnerability Score|First Observed|Ip Address|Is Active|Last Observed|Port|Protocol|Service Id|Service Name|Service Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| SSHWeakMACAlgorithmsEnabled,<br/>SshServer,<br/>OpenSSH | Acme | serviceKey: 1.1.1.1:22<br/>serviceKeyType: IP<br/>businessUnits: {'name': 'Acme'}<br/>providerDetails: {'name': 'AWS', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}<br/>certificates: <br/>domains: <br/>ips: {'ip': 873887795, 'protocol': 'TCP', 'provider': 'AWS', 'geolocation': {'latitude': 39.0438, 'longitude': -77.4879, 'countryCode': 'US', 'city': 'ASHBURN', 'regionCode': 'VA', 'timeZone': None}, 'activityStatus': 'Active', 'lastObserved': 1663026500000, 'firstObserved': 1662774169000}<br/>classifications: {'name': 'SshServer', 'activityStatus': 'Active', 'values': [{'jsonValue': '{"version":"2.0","serverVersion":"OpenSSH_7.6p1","extraInfo":"Ubuntu-4ubuntu0.7"}', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}], 'firstObserved': 1662774120000, 'lastObserved': 1663026480000},<br/>{'name': 'SSHWeakMACAlgorithmsEnabled', 'activityStatus': 'Active', 'values': [{'jsonValue': '{}', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}], 'firstObserved': 1662774120000, 'lastObserved': 1663026480000},<br/>{'name': 'OpenSSH', 'activityStatus': 'Active', 'values': [{'jsonValue': '{"version":"7.6"}', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}], 'firstObserved': 1662774120000, 'lastObserved': 1663026480000}<br/>tlsVersions: <br/>inferredCvesObserved: {'inferredCve': {'cveId': 'CVE-2020-15778', 'cvssScoreV2': 6.8, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 7.8, 'cveSeverityV3': 'HIGH', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2021-41617', 'cvssScoreV2': 4.4, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 7.0, 'cveSeverityV3': 'HIGH', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6110', 'cvssScoreV2': 4.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 6.8, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6109', 'cvssScoreV2': 4.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 6.8, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2020-14145', 'cvssScoreV2': 4.3, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.9, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6111', 'cvssScoreV2': 5.8, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.9, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2018-20685', 'cvssScoreV2': 2.6, 'cveSeverityV2': 'LOW', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2018-15919', 'cvssScoreV2': 5.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2016-20012', 'cvssScoreV2': 4.3, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2018-15473', 'cvssScoreV2': 5.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2021-36368', 'cvssScoreV2': 2.6, 'cveSeverityV2': 'LOW', 'cvssScoreV3': 3.7, 'cveSeverityV3': 'LOW', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}<br/>enrichedObservationSource: CLOUD<br/>ip_ranges: {} | ColocatedOnIp | Amazon Web Services | CVE-2020-15778,<br/>CVE-2021-41617,<br/>CVE-2019-6110,<br/>CVE-2019-6109,<br/>CVE-2020-14145,<br/>CVE-2019-6111,<br/>CVE-2018-20685,<br/>CVE-2018-15919,<br/>CVE-2016-20012,<br/>CVE-2018-15473,<br/>CVE-2021-36368 | 7.8 | 1662774120000 | 1.1.1.1 | Active | 1663026480000 | 22 | TCP | 94232f8a-f001-3292-aa65-63fa9d981427 | SSH Server at 1.1.1.1:22 | SshServer |


### asm-list-external-ip-address-range

***
Get a list of all your internet exposures filtered by business units and organization handles. Maximum result limit is 100 ranges.


#### Base Command

`asm-list-external-ip-address-range`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.ExternalIpAddressRange.range_id | String | External IP address range UUID. | 
| ASM.ExternalIpAddressRange.first_ip | String | First IP address of the external IP address range. | 
| ASM.ExternalIpAddressRange.last_ip | String | Last IP address of the external IP address range. | 
| ASM.ExternalIpAddressRange.ips_count | Number | Number of IP addresses of the external IP address range. | 
| ASM.ExternalIpAddressRange.active_responsive_ips_count | Number | The number of IPs in the external address range that are actively responsive. | 
| ASM.ExternalIpAddressRange.date_added | Date | Date the external IP address range was added. | 
| ASM.ExternalIpAddressRange.business_units | String | External IP address range associated business units. | 
| ASM.ExternalIpAddressRange.organization_handles | String | External IP address range associated organization handles. | 

#### Command example

```!asm-list-external-ip-address-range```

#### Context Example

```json
{
    "ASM": {
        "ExternalIpAddressRange": [
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "VanDelay Industries"
                ],
                "date_added": 1663031000145,
                "first_ip": "1.1.1.1",
                "ips_count": 64,
                "last_ip": "1.1.1.1",
                "organization_handles": [
                    "MAINT-HK-PCCW-BIA-CS",
                    "BNA2-AP",
                    "TA66-AP"
                ],
                "range_id": "4da29b7f-3086-3b52-981b-aa8ee5da1e60"
            },
            {
                "active_responsive_ips_count": 0,
                "business_units": [
                    "VanDelay Industries"
                ],
                "date_added": 1663031000144,
                "first_ip": "1.1.1.1",
                "ips_count": 16,
                "last_ip": "1.1.1.1",
                "organization_handles": [
                    "AR17615-RIPE",
                    "EASYNET-UK-MNT",
                    "JW372-RIPE",
                    "EH92-RIPE"
                ],
                "range_id": "6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5"
            }
        ]
    }
}
```

#### Human Readable Output

>### External IP Address Ranges
>
>|Active Responsive Ips Count|Business Units|Date Added|First Ip|Ips Count|Last Ip|Organization Handles|Range Id|
>|---|---|---|---|---|---|---|---|
>| 0 | VanDelay Industries | 1663031000145 | 1.1.1.1 | 64 | 1.1.1.1 | MAINT-HK-PCCW-BIA-CS,<br/>BNA2-AP,<br/>TA66-AP | 4da29b7f-3086-3b52-981b-aa8ee5da1e60 |
>| 0 | VanDelay Industries | 1663031000144 | 1.1.1.1 | 16 | 1.1.1.1 | AR17615-RIPE,<br/>EASYNET-UK-MNT,<br/>JW372-RIPE,<br/>EH92-RIPE | 6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5 |


### asm-get-external-ip-address-range

***
Get external IP address range details according to the range IDs.


#### Base Command

`asm-get-external-ip-address-range`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id | A string representing the range ID for which you want to get the details. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.ExternalIpAddressRange.range_id | String | External IP address range UUID. | 
| ASM.ExternalIpAddressRange.first_ip | String | First IP address of the external IP address range. | 
| ASM.ExternalIpAddressRange.last_ip | String | Last IP address of the external IP address range. | 
| ASM.ExternalIpAddressRange.ips_count | Number | Number of IP addresses of the external IP address range. | 
| ASM.ExternalIpAddressRange.active_responsive_ips_count | Number | The number of IPs in the external address range that are actively responsive. | 
| ASM.ExternalIpAddressRange.date_added | Date | Date the external IP address range was added. | 
| ASM.ExternalIpAddressRange.business_units | String | External IP address range associated business units. | 
| ASM.ExternalIpAddressRange.organization_handles | String | External IP address range associated organization handles. | 
| ASM.ExternalIpAddressRange.details | String | Additional information. | 

#### Command example

```!asm-get-external-ip-address-range range_id=4da29b7f-3086-3b52-981b-aa8ee5da1e60```

#### Context Example

```json
{
    "ASM": {
        "ExternalIpAddressRange": {
            "active_responsive_ips_count": 0,
            "business_units": [
                "VanDelay Industries"
            ],
            "date_added": 1663031000145,
            "details": {
                "networkRecords": [
                    {
                        "firstIp": "1.1.1.1",
                        "handle": "1.1.1.1 - 1.1.1.1",
                        "lastChanged": 1663030241931,
                        "lastIp": "1.1.1.1",
                        "name": "SEARS-HK",
                        "organizationRecords": [
                            {
                                "address": "",
                                "dateAdded": 1663029346957,
                                "email": "noc@acme.com",
                                "firstRegistered": null,
                                "formattedName": "",
                                "handle": "MAINT-HK-PCCW-BIA-CS",
                                "kind": "group",
                                "lastChanged": null,
                                "org": "",
                                "phone": "",
                                "remarks": "",
                                "roles": [
                                    "registrant"
                                ]
                            },
                            {
                                "address": "27/F, PCCW Tower, Taikoo Place,\n979 King's Road, Quarry Bay, HK          ",
                                "dateAdded": 1663029346957,
                                "email": "cs@acme.com",
                                "firstRegistered": 1220514857000,
                                "formattedName": "BIZ NETVIGATOR ADMINISTRATORS",
                                "handle": "BNA2-AP",
                                "kind": "group",
                                "lastChanged": 1514892767000,
                                "org": "",
                                "phone": "+852-2888-6932",
                                "remarks": "",
                                "roles": [
                                    "administrative"
                                ]
                            },
                            {
                                "address": "HKT Limited\nPO Box 9896 GPO          ",
                                "dateAdded": 1663029346957,
                                "email": "noc@acme.com",
                                "firstRegistered": 1220514856000,
                                "formattedName": "TECHNICAL ADMINISTRATORS",
                                "handle": "TA66-AP",
                                "kind": "group",
                                "lastChanged": 1468555410000,
                                "org": "",
                                "phone": "+852-2883-5151",
                                "remarks": "",
                                "roles": [
                                    "technical"
                                ]
                            }
                        ],
                        "remarks": "Sears Holdings Global Sourcing Ltd",
                        "whoIsServer": "whois.apnic.net"
                    }
                ]
            },
            "first_ip": "1.1.1.1",
            "ips_count": 64,
            "last_ip": "1.1.1.1",
            "organization_handles": [
                "MAINT-HK-PCCW-BIA-CS",
                "BNA2-AP",
                "TA66-AP"
            ],
            "range_id": "4da29b7f-3086-3b52-981b-aa8ee5da1e60"
        }
    }
}
```

#### Human Readable Output

>### External IP Address Range

>|Active Responsive Ips Count|Business Units|Date Added|Details|First Ip|Ips Count|Last Ip|Organization Handles|Range Id|
>|---|---|---|---|---|---|---|---|---|
>| 0 | VanDelay Industries | 1663031000145 | networkRecords: {'handle': '1.1.1.1 - 1.1.1.1', 'firstIp': '1.1.1.1', 'lastIp': '1.1.1.1', 'name': 'SEARS-HK', 'whoIsServer': 'whois.apnic.net', 'lastChanged': 1663030241931, 'organizationRecords': [{'handle': 'MAINT-HK-PCCW-BIA-CS', 'dateAdded': 1663029346957, 'address': '', 'email': 'noc@acme.com', 'phone': '', 'org': '', 'formattedName': '', 'kind': 'group', 'roles': ['registrant'], 'lastChanged': None, 'firstRegistered': None, 'remarks': ''}, {'handle': 'BNA2-AP', 'dateAdded': 1663029346957, 'address': "27/F, PCCW Tower, Taikoo Place,\n979 King's Road, Quarry Bay, HK          ", 'email': 'cs@acme.com', 'phone': '+852-2888-6932', 'org': '', 'formattedName': 'BIZ NETVIGATOR ADMINISTRATORS', 'kind': 'group', 'roles': ['administrative'], 'lastChanged': 1514892767000, 'firstRegistered': 1220514857000, 'remarks': ''}, {'handle': 'TA66-AP', 'dateAdded': 1663029346957, 'address': 'HKT Limited\nPO Box 9896 GPO          ', 'email': 'noc@acme.com', 'phone': '+852-2883-5151', 'org': '', 'formattedName': 'TECHNICAL ADMINISTRATORS', 'kind': 'group', 'roles': ['technical'], 'lastChanged': 1468555410000, 'firstRegistered': 1220514856000, 'remarks': ''}], 'remarks': 'Sears Holdings Global Sourcing Ltd'} | 1.1.1.1 | 64 | 1.1.1.1 | MAINT-HK-PCCW-BIA-CS,<br/>BNA2-AP,<br/>TA66-AP | 4da29b7f-3086-3b52-981b-aa8ee5da1e60 |


### asm-list-asset-internet-exposure

***
Get a list of all your internet exposures filtered by IP address, domain, type, asm id, IPv6 address, AWS/GCP/Azure tags, has XDR agent, Externally detected providers, Externally inferred cves, Business units list, has BU overrides and/or if there is an active external service. Maximum result limit is 100 assets.

#### Base Command

`asm-list-asset-internet-exposure`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address on which to search. | Optional | 
| name | Name of the asset on which to search. | Optional | 
| type | Type of the external service. Possible values are: certificate, cloud_compute_instance, on_prem, domain, unassociated_responsive_ip. | Optional | 
| has_active_external_services | Whether the internet exposure has an active external service. Possible values are: yes, no. | Optional | 
| search_from | Represents the start offset index of results. Default is 0. | Optional | 
| search_to | Represents the end offset index of results. | Optional | 
| asm_id_list | List of asm ids. | Optional | 
| ipv6_address | IPv6 address on which to search. | Optional | 
| gcp_cloud_tags | Search based on GCP cloud tags. | Optional | 
| aws_cloud_tags | Search based on AWS cloud tags. | Optional | 
| azure_cloud_tags | Search based on AZURE cloud tags. | Optional | 
| has_xdr_agent | Search based on xdr agent. | Optional | 
| externally_detected_providers | Search on externally detected providers. | Optional | 
| externally_inferred_cves | Search on externally inferred cve. | Optional | 
| business_units_list | Search on Business units list. | Optional | 
| has_bu_overrides | Whether it has BU overrides. Possible values are: True, False. | Optional | 
| mac_address | Search based on MAC address. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.AssetInternetExposure.asm_ids | String | Attack surface management UUID. | 
| ASM.AssetInternetExposure.name | String | Name of the exposed asset. | 
| ASM.AssetInternetExposure.asset_type | String | Type of the exposed asset. | 
| ASM.AssetInternetExposure.cloud_provider | Unknown | The cloud provider used to collect these cloud assets as either GCP, AWS, or Azure. | 
| ASM.AssetInternetExposure.region | Unknown | Displays the region as provided by the cloud provider. | 
| ASM.AssetInternetExposure.last_observed | Unknown | Last time the exposure was observed. | 
| ASM.AssetInternetExposure.first_observed | Unknown | First time the exposure was observed. | 
| ASM.AssetInternetExposure.has_active_externally_services | Boolean | Whether the internet exposure is associated with an active external service\(s\). | 
| ASM.AssetInternetExposure.has_xdr_agent | String | Whether the internet exposure asset has an XDR agent. | 
| ASM.AssetInternetExposure.cloud_id | Unknown | Displays the resource ID as provided from the cloud provider. | 
| ASM.AssetInternetExposure.domain_resolves | Boolean | Whether the asset domain is resolvable. | 
| ASM.AssetInternetExposure.operation_system | Unknown | The operating system reported by the source for this asset. | 
| ASM.AssetInternetExposure.agent_id | Unknown | The endpoint ID if there is an endpoint installed on this asset. | 
| ASM.AssetInternetExposure.externally_detected_providers | String | The provider of the asset as determined by an external assessment. | 
| ASM.AssetInternetExposure.service_type | String | Type of the asset. | 
| ASM.AssetInternetExposure.externally_inferred_cves | String | If the internet exposure has associated CVEs. | 
| ASM.AssetInternetExposure.ips | String | IP addresses associated with the internet exposure. | 


#### Command example

```!asm-list-asset-internet-exposure name="acme.com" type=certificate has_active_external_services=no```

#### Context Example

```json
{
    "ASM": {
        "AssetInternetExposure": [
            {
                "agent_id": null,
                "asm_ids": [
                    "cfa1cd5a-77f1-3963-8557-7f652309a143"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "Acme",
                    "VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.digital-dev.acme.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            },
            {
                "agent_id": null,
                "asm_ids": [
                    "78a11e94-58a9-329c-99ca-e527d2db6cfb"
                ],
                "asm_va_score": null,
                "asset_type": "CERTIFICATE",
                "business_units": [
                    "Acme",
                    "VanDelay Industries"
                ],
                "certificate_algorithm": "SHA256withRSA",
                "certificate_classifications": [
                    "LongExpiration",
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "DigiCert",
                "cloud_id": null,
                "cloud_provider": null,
                "domain_resolves": false,
                "externally_detected_providers": [],
                "externally_inferred_cves": [],
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "iot_category": null,
                "iot_model": null,
                "iot_profile": null,
                "ip_ranges": [],
                "ips": [],
                "last_observed": null,
                "mac_addresses": [],
                "management_status": [],
                "name": "*.digital-prod.acme.com",
                "operation_system": null,
                "region": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Asset Internet Exposures
>
>|Asm Ids|Asset Type|Business Units|Certificate Algorithm|Certificate Classifications|Certificate Issuer|Domain Resolves|Has Active Externally Services|Has Xdr Agent|Name|Sensor|
>|---|---|---|---|---|---|---|---|---|---|---|
>| cfa1cd5a-77f1-3963-8557-7f652309a143 | CERTIFICATE | Acme,<br/>VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | DigiCert | false | false | NA | *.digital-dev.acme.com | XPANSE |
>| 78a11e94-58a9-329c-99ca-e527d2db6cfb | CERTIFICATE | Acme,<br/>VanDelay Industries | SHA256withRSA | LongExpiration,<br/>Wildcard,<br/>Expired | DigiCert | false | false | NA | *.digital-prod.acme.com | XPANSE |


### asm-get-asset-internet-exposure

***
Get internet exposure asset details according to the asset ID.


#### Base Command

`asm-get-asset-internet-exposure`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_id | A string representing the asset ID for which you want to get the details. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.AssetInternetExposure.asm_ids | String | Attack surface management UUID. | 
| ASM.AssetInternetExposure.name | String | Name of the exposed asset. | 
| ASM.AssetInternetExposure.type | String | Type of the exposed asset. | 
| ASM.AssetInternetExposure.last_observed | Unknown | Last time the exposure was observed. | 
| ASM.AssetInternetExposure.first_observed | Unknown | First time the exposure was observed. | 
| ASM.AssetInternetExposure.created | Date | Date the ASM issue was created. | 
| ASM.AssetInternetExposure.business_units | String | Asset associated business units. | 
| ASM.AssetInternetExposure.domain | Unknown | Asset associated domain. | 
| ASM.AssetInternetExposure.certificate_issuer | String | Asset certificate issuer. | 
| ASM.AssetInternetExposure.certificate_algorithm | String | Asset certificate algorithm. | 
| ASM.AssetInternetExposure.certificate_classifications | String | Asset certificate classifications. | 
| ASM.AssetInternetExposure.resolves | Boolean | Whether the asset has DNS resolution. | 
| ASM.AssetInternetExposure.details | Unknown | Additional details. | 
| ASM.AssetInternetExposure.externally_inferred_vulnerability_score | Unknown | Asset vulnerability score. | 

#### Command example

```!asm-get-asset-internet-exposure asm_id=3c176460-8735-333c-b618-8262e2fb660c```

#### Context Example

```json
{
    "ASM": {
        "AssetInternetExposure": {
            "active_external_services_types": [],
            "active_service_ids": [],
            "all_service_ids": [],
            "asm_ids": "3c176460-8735-333c-b618-8262e2fb660c",
            "business_units": [
                "Acme"
            ],
            "certificate_algorithm": "SHA1withRSA",
            "certificate_classifications": [
                "Wildcard",
                "Expired",
                "InsecureSignature"
            ],
            "certificate_issuer": "Thawte",
            "created": 1663030146931,
            "details": {
                "businessUnits": [
                    {
                        "name": "Acme"
                    }
                ],
                "certificateDetails": {
                    "formattedIssuerOrg": "Thawte",
                    "issuer": "C=US,O=Thawte\\, Inc.,CN=Thawte SSL CA",
                    "issuerAlternativeNames": "",
                    "issuerCountry": "US",
                    "issuerEmail": null,
                    "issuerLocality": null,
                    "issuerName": "Thawte SSL CA",
                    "issuerOrg": "Thawte\\\\, Inc.",
                    "issuerOrgUnit": null,
                    "issuerState": null,
                    "md5Fingerprint": "498ec19ebd6c6883ecd43d064e713002",
                    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp21W/QVHuo0Nyy9l6Qp6Ye7yniuCccplWLdkL34pB0roNWBiklLJFftFTXJLtUuYEBhEbUtOPtNr5QRZFo+LQSj+JMQsGajEgNvIIMDms2xtc+vYkuJeNRsN/0zRm8iBjCNEZ0zBbWdupO6xee+Lngq5RiyRzAN2+Q5HlmHmVOcc7NtY5VIQhajp3a5Gc7tmLXa7ZxwQb+afdlpmE0iv4ZxmXFyHwlPXUlIxfETDDjtv2EzAgrnpZ5juo7TEFZA7AjsT0lO6cC2qPE9x9kC02PeC1Heg4hWf70CsXcKQBsprLqusrPYM9+OYfZnj+Dq9j6FjZD314Nz4qTGwmZrwDQIDAQAB",
                    "publicKeyAlgorithm": "RSA",
                    "publicKeyBits": 2048,
                    "publicKeyModulus": "a76d56fd0547ba8d0dcb2f65e90a7a61eef29e2b8271ca6558b7642f7e29074ae83560629252c915fb454d724bb54b981018446d4b4e3ed36be50459168f8b4128fe24c42c19a8c480dbc820c0e6b36c6d73ebd892e25e351b0dff4cd19bc8818c2344674cc16d676ea4eeb179ef8b9e0ab9462c91cc0376f90e479661e654e71cecdb58e5521085a8e9ddae4673bb662d76bb671c106fe69f765a661348afe19c665c5c87c253d75252317c44c30e3b6fd84cc082b9e96798eea3b4c415903b023b13d253ba702daa3c4f71f640b4d8f782d477a0e2159fef40ac5dc29006ca6b2eabacacf60cf7e3987d99e3f83abd8fa163643df5e0dcf8a931b0999af00d",
                    "publicKeyRsaExponent": 65537,
                    "publicKeySpki": "Up3fHwOddA9cXEeO4XBOgn63bfnvkXsOrOv6AycwQAk=",
                    "serialNumber": "91384582774546160650506315451812470612",
                    "sha1Fingerprint": "77d025c36f055e254063ae2ac3625fd4bf4507fb",
                    "sha256Fingerprint": "9a37c952ee1169cfa6e91efb57fe6d405d1ca48b26a714e9a46f008c15ea62e8",
                    "signatureAlgorithm": "SHA1withRSA",
                    "subject": "C=US,ST=New Jersey,L=Wayne,O=Acme,OU=MIS,CN=*.acme.com",
                    "subjectAlternativeNames": "*.acme.com",
                    "subjectCountry": "US",
                    "subjectEmail": null,
                    "subjectLocality": "Wayne",
                    "subjectName": "*.acme.com",
                    "subjectOrg": "Acme",
                    "subjectOrgUnit": "MIS",
                    "subjectState": "New Jersey",
                    "validNotAfter": 1444780799000,
                    "validNotBefore": 1413158400000,
                    "version": "3"
                },
                "dnsZone": null,
                "domain": null,
                "domainAssetType": null,
                "domainDetails": null,
                "inferredCvesObserved": [],
                "ip_ranges": {},
                "isPaidLevelDomain": false,
                "latestSampledIp": null,
                "providerDetails": [],
                "recentIps": [],
                "subdomainMetadata": null,
                "topLevelAssetMapperDomain": null
            },
            "domain": null,
            "external_services": [],
            "externally_detected_providers": [],
            "externally_inferred_cves": [],
            "externally_inferred_vulnerability_score": null,
            "first_observed": null,
            "ips": [],
            "last_observed": null,
            "name": "*.acme.com",
            "resolves": false,
            "type": "Certificate"
        }
    }
}
```

#### Human Readable Output

>### Asset Internet Exposure
>
>|Asm Ids|Business Units|Certificate Algorithm|Certificate Classifications|Certificate Issuer|Created|Details|Name|Resolves|Type|
>|---|---|---|---|---|---|---|---|---|---|
>| 3c176460-8735-333c-b618-8262e2fb660c | Acme | SHA1withRSA | Wildcard,<br/>Expired,<br/>InsecureSignature | Thawte | 1663030146931 | providerDetails: <br/>domain: null<br/>topLevelAssetMapperDomain: null<br/>domainAssetType: null<br/>isPaidLevelDomain: false<br/>domainDetails: null<br/>dnsZone: null<br/>latestSampledIp: null<br/>subdomainMetadata: null<br/>recentIps: <br/>businessUnits: {'name': 'Acme'}<br/>certificateDetails: {"issuer": "C=US,O=Thawte\\, Inc.,CN=Thawte SSL CA", "issuerAlternativeNames": "", "issuerCountry": "US", "issuerEmail": null, "issuerLocality": null, "issuerName": "Thawte SSL CA", "issuerOrg": "Thawte\\\\, Inc.", "formattedIssuerOrg": "Thawte", "issuerOrgUnit": null, "issuerState": null, "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp21W/QVHuo0Nyy9l6Qp6Ye7yniuCccplWLdkL34pB0roNWBiklLJFftFTXJLtUuYEBhEbUtOPtNr5QRZFo+LQSj+JMQsGajEgNvIIMDms2xtc+vYkuJeNRsN/0zRm8iBjCNEZ0zBbWdupO6xee+Lngq5RiyRzAN2+Q5HlmHmVOcc7NtY5VIQhajp3a5Gc7tmLXa7ZxwQb+afdlpmE0iv4ZxmXFyHwlPXUlIxfETDDjtv2EzAgrnpZ5juo7TEFZA7AjsT0lO6cC2qPE9x9kC02PeC1Heg4hWf70CsXcKQBsprLqusrPYM9+OYfZnj+Dq9j6FjZD314Nz4qTGwmZrwDQIDAQAB", "publicKeyAlgorithm": "RSA", "publicKeyRsaExponent": 65537, "signatureAlgorithm": "SHA1withRSA", "subject": "C=US,ST=New Jersey,L=Wayne,O=Acme,OU=MIS,CN=*.acme.com", "subjectAlternativeNames": "*.acme.com", "subjectCountry": "US", "subjectEmail": null, "subjectLocality": "Wayne", "subjectName": "*.acme.com", "subjectOrg": "Acme", "subjectOrgUnit": "MIS", "subjectState": "New Jersey", "serialNumber": "91384582774546160650506315451812470612", "validNotBefore": 1413158400000, "validNotAfter": 1444780799000, "version": "3", "publicKeyBits": 2048, "publicKeyModulus": "a76d56fd0547ba8d0dcb2f65e90a7a61eef29e2b8271ca6558b7642f7e29074ae83560629252c915fb454d724bb54b981018446d4b4e3ed36be50459168f8b4128fe24c42c19a8c480dbc820c0e6b36c6d73ebd892e25e351b0dff4cd19bc8818c2344674cc16d676ea4eeb179ef8b9e0ab9462c91cc0376f90e479661e654e71cecdb58e5521085a8e9ddae4673bb662d76bb671c106fe69f765a661348afe19c665c5c87c253d75252317c44c30e3b6fd84cc082b9e96798eea3b4c415903b023b13d253ba702daa3c4f71f640b4d8f782d477a0e2159fef40ac5dc29006ca6b2eabacacf60cf7e3987d99e3f83abd8fa163643df5e0dcf8a931b0999af00d", "publicKeySpki": "Up3fHwOddA9cXEeO4XBOgn63bfnvkXsOrOv6AycwQAk=", "sha1Fingerprint": "77d025c36f055e254063ae2ac3625fd4bf4507fb", "sha256Fingerprint": "9a37c952ee1169cfa6e91efb57fe6d405d1ca48b26a714e9a46f008c15ea62e8", "md5Fingerprint": "498ec19ebd6c6883ecd43d064e713002"}<br/>inferredCvesObserved: <br/>ip_ranges: {} | *.acme.com | false | Certificate |


### asm-list-alerts

***
Get a list of all your ASM alerts filtered by alert IDs, severity and/or creation time. Can also sort by creation time or severity. Maximum result limit is 100 assets.

#### Base Command

`asm-list-alerts`

#### Input

| **Argument Name**     | **Description**                                                                                                                                                                                                                                   | **Required** |
|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| alert_id_list         | Comma-separated list of alert IDs.                                                                                                                                                                                                 | Optional | 
| severity              | Comma-separated list of alert severities (valid values are low, medium, high, critical, informational).                                                                                                                                  | Optional | 
| tags                  | Comma-separated list of alert tags. These should include the tag prefix, ex. AT:Asset Tag.                                                                                                                                             | Optional | 
| status                | Comma-separated list of the alert status. Possible values are: new, reopened, under_investigation, resolved_no_longer_observed, resolved_no_risk, resolved_risk_accepted, resolved_contested_asset, resolved_remediated_automatically, resolved. | Optional | 
| business_units_list   | Comma-separated list business units.                                                                                                                                                                                            | Optional | 
| case_id_list          | Comma-separated list of case (incident) IDs.                                                                                                                                                                                       | Optional | 
| lte_creation_time     | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or before the specified date/time will be retrieved.                                                                                                                | Optional | 
| gte_creation_time     | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or after the specified date/time will be retrieved.                                                                                                                 | Optional | 
| sort_by_creation_time | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). Possible values are: asc, desc.                                                                                                 | Optional | 
| sort_by_severity      | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). Possible values are: asc, desc.                                                                                                 | Optional | 
| page                  | Page number (for pagination). The default is 0 (the first page). Default is 0.                                                                                                                                                                    | Optional | 
| limit                 | Maximum number of incidents to return per page. The default and maximum is 100. Default is 100.                                                                                                                                                   | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.Alert.alert_id | String | A unique identifier that Cortex XSIAM assigns to each alert. | 
| ASM.Alert.severity | String | The severity that was assigned to this alert when it was triggered \(Options are Informational, Low, Medium, High, Critical, or Unknown\). | 
| ASM.Alert.external_id | String | The alert ID as recorded in the detector from which this alert was sent. | 
| ASM.Alert.name | String | Summary of the ASM internet exposure alert. | 
| ASM.Alert.description | String | More detailed explanation of internet exposure alert. | 
| ASM.Alert.host_name | String | The hostname of the endpoint or server on which this alert triggered. | 
| ASM.Alert.dynamic_fields | Unknown | Alert fields pulled from Cortex XSOAR context. | 
| ASM.Alert.events | Unknown | Individual events that comprise the alert. | 
| ASM.Alert.detection_timestamp | Date | Date the alert was created. | 

#### Command example

```!asm-list-alerts limit=2 severity=high sort_by_creation_time=asc```

#### Context Example

```json
{
    "ASM": {
        "Alerts": [
            {
                "action": "NOT_AVAILABLE",
                "action_pretty": "N/A",
                "agent_data_collection_status": null,
                "agent_device_domain": null,
                "agent_fqdn": null,
                "agent_ip_addresses_v6": null,
                "agent_os_sub_type": null,
                "agent_os_type": "NO_HOST",
                "agent_version": null,
                "alert_id": "231",
                "alert_type": "Unclassified",
                "attempt_counter": null,
                "bioc_category_enum_key": null,
                "bioc_indicator": null,
                "category": null,
                "deduplicate_tokens": null,
                "description": "Networking and security infrastructure, such as firewalls and routers, generally should not have their administration panels open to public Internet. Compromise of these devices, often though password guessing or vulnerability exploitation, provides privileged access to an enterprise network.",
                "detection_timestamp": 1659452808759,
                "dynamic_fields": null,
                "end_match_attempt_ts": null,
                "endpoint_id": null,
                "events": [
                    {
                        "action_country": "UNKNOWN",
                        "action_external_hostname": null,
                        "action_file_macro_sha256": null,
                        "action_file_md5": null,
                        "action_file_name": null,
                        "action_file_path": null,
                        "action_file_sha256": null,
                        "action_local_ip": null,
                        "action_local_ip_v6": null,
                        "action_local_port": null,
                        "action_process_causality_id": null,
                        "action_process_image_command_line": null,
                        "action_process_image_name": null,
                        "action_process_image_sha256": null,
                        "action_process_instance_id": null,
                        "action_process_signature_status": "N/A",
                        "action_process_signature_vendor": null,
                        "action_registry_data": null,
                        "action_registry_full_key": null,
                        "action_registry_key_name": null,
                        "action_registry_value_name": null,
                        "action_remote_ip": null,
                        "action_remote_ip_v6": null,
                        "action_remote_port": 80,
                        "actor_causality_id": null,
                        "actor_process_causality_id": null,
                        "actor_process_command_line": null,
                        "actor_process_image_md5": null,
                        "actor_process_image_name": null,
                        "actor_process_image_path": null,
                        "actor_process_image_sha256": null,
                        "actor_process_instance_id": null,
                        "actor_process_os_pid": null,
                        "actor_process_signature_status": "N/A",
                        "actor_process_signature_vendor": null,
                        "actor_thread_thread_id": null,
                        "agent_host_boot_time": null,
                        "agent_install_type": "NA",
                        "association_strength": null,
                        "causality_actor_causality_id": null,
                        "causality_actor_process_command_line": null,
                        "causality_actor_process_execution_time": null,
                        "causality_actor_process_image_md5": null,
                        "causality_actor_process_image_name": null,
                        "causality_actor_process_image_path": null,
                        "causality_actor_process_image_sha256": null,
                        "causality_actor_process_signature_status": "N/A",
                        "causality_actor_process_signature_vendor": null,
                        "cloud_provider": null,
                        "cluster_name": null,
                        "container_id": null,
                        "contains_featured_host": "NO",
                        "contains_featured_ip": "NO",
                        "contains_featured_user": "NO",
                        "dns_query_name": null,
                        "dst_action_country": null,
                        "dst_action_external_hostname": null,
                        "dst_action_external_port": null,
                        "dst_agent_id": null,
                        "dst_association_strength": null,
                        "dst_causality_actor_process_execution_time": null,
                        "event_id": null,
                        "event_sub_type": null,
                        "event_timestamp": 1659452808759,
                        "event_type": null,
                        "fw_app_category": null,
                        "fw_app_id": null,
                        "fw_app_subcategory": null,
                        "fw_app_technology": null,
                        "fw_device_name": null,
                        "fw_email_recipient": null,
                        "fw_email_sender": null,
                        "fw_email_subject": null,
                        "fw_interface_from": null,
                        "fw_interface_to": null,
                        "fw_is_phishing": "N/A",
                        "fw_misc": null,
                        "fw_rule": null,
                        "fw_rule_id": null,
                        "fw_serial_number": null,
                        "fw_url_domain": null,
                        "fw_vsys": null,
                        "fw_xff": null,
                        "identity_sub_type": null,
                        "identity_type": null,
                        "image_name": null,
                        "module_id": null,
                        "operation_name": null,
                        "os_actor_causality_id": null,
                        "os_actor_effective_username": null,
                        "os_actor_process_causality_id": null,
                        "os_actor_process_command_line": null,
                        "os_actor_process_image_name": null,
                        "os_actor_process_image_path": null,
                        "os_actor_process_image_sha256": null,
                        "os_actor_process_instance_id": null,
                        "os_actor_process_os_pid": null,
                        "os_actor_process_signature_status": "N/A",
                        "os_actor_process_signature_vendor": null,
                        "os_actor_thread_thread_id": null,
                        "project": null,
                        "referenced_resource": null,
                        "resource_sub_type": null,
                        "resource_type": null,
                        "story_id": null,
                        "user_agent": null,
                        "user_name": null
                    }
                ],
                "external_id": "FAKE-GUID",
                "filter_rule_id": null,
                "host_ip": null,
                "host_name": null,
                "is_pcap": false,
                "is_whitelisted": false,
                "last_modified_ts": 1660240725450,
                "local_insert_ts": 1659455267908,
                "mac": null,
                "mac_addresses": null,
                "matching_service_rule_id": null,
                "matching_status": "MATCHED",
                "mitre_tactic_id_and_name": null,
                "mitre_technique_id_and_name": null,
                "name": "Networking Infrastructure",
                "original_tags": null,
                "resolution_comment": "ASM alert resolution",
                "resolution_status": "STATUS_070_RESOLVED_OTHER",
                "severity": "high",
                "source": "ASM",
                "starred": false,
                "tags": null
            },
            {
                "action": "NOT_AVAILABLE",
                "action_pretty": "N/A",
                "agent_data_collection_status": null,
                "agent_device_domain": null,
                "agent_fqdn": null,
                "agent_ip_addresses_v6": null,
                "agent_os_sub_type": null,
                "agent_os_type": "NO_HOST",
                "agent_version": null,
                "alert_id": "33",
                "alert_type": "Unclassified",
                "attempt_counter": null,
                "bioc_category_enum_key": null,
                "bioc_indicator": null,
                "category": null,
                "deduplicate_tokens": null,
                "description": "Networking and security infrastructure, such as firewalls and routers, generally should not have their administration panels open to public Internet. Compromise of these devices, often though password guessing or vulnerability exploitation, provides privileged access to an enterprise network.",
                "detection_timestamp": 1659452809020,
                "dynamic_fields": null,
                "end_match_attempt_ts": null,
                "endpoint_id": null,
                "events": [
                    {
                        "action_country": "UNKNOWN",
                        "action_external_hostname": null,
                        "action_file_macro_sha256": null,
                        "action_file_md5": null,
                        "action_file_name": null,
                        "action_file_path": null,
                        "action_file_sha256": null,
                        "action_local_ip": null,
                        "action_local_ip_v6": null,
                        "action_local_port": null,
                        "action_process_causality_id": null,
                        "action_process_image_command_line": null,
                        "action_process_image_name": null,
                        "action_process_image_sha256": null,
                        "action_process_instance_id": null,
                        "action_process_signature_status": "N/A",
                        "action_process_signature_vendor": null,
                        "action_registry_data": null,
                        "action_registry_full_key": null,
                        "action_registry_key_name": null,
                        "action_registry_value_name": null,
                        "action_remote_ip": null,
                        "action_remote_ip_v6": null,
                        "action_remote_port": 80,
                        "actor_causality_id": null,
                        "actor_process_causality_id": null,
                        "actor_process_command_line": null,
                        "actor_process_image_md5": null,
                        "actor_process_image_name": null,
                        "actor_process_image_path": null,
                        "actor_process_image_sha256": null,
                        "actor_process_instance_id": null,
                        "actor_process_os_pid": null,
                        "actor_process_signature_status": "N/A",
                        "actor_process_signature_vendor": null,
                        "actor_thread_thread_id": null,
                        "agent_host_boot_time": null,
                        "agent_install_type": "NA",
                        "association_strength": null,
                        "causality_actor_causality_id": null,
                        "causality_actor_process_command_line": null,
                        "causality_actor_process_execution_time": null,
                        "causality_actor_process_image_md5": null,
                        "causality_actor_process_image_name": null,
                        "causality_actor_process_image_path": null,
                        "causality_actor_process_image_sha256": null,
                        "causality_actor_process_signature_status": "N/A",
                        "causality_actor_process_signature_vendor": null,
                        "cloud_provider": null,
                        "cluster_name": null,
                        "container_id": null,
                        "contains_featured_host": "NO",
                        "contains_featured_ip": "NO",
                        "contains_featured_user": "NO",
                        "dns_query_name": null,
                        "dst_action_country": null,
                        "dst_action_external_hostname": null,
                        "dst_action_external_port": null,
                        "dst_agent_id": null,
                        "dst_association_strength": null,
                        "dst_causality_actor_process_execution_time": null,
                        "event_id": null,
                        "event_sub_type": null,
                        "event_timestamp": 1659452809020,
                        "event_type": null,
                        "fw_app_category": null,
                        "fw_app_id": null,
                        "fw_app_subcategory": null,
                        "fw_app_technology": null,
                        "fw_device_name": null,
                        "fw_email_recipient": null,
                        "fw_email_sender": null,
                        "fw_email_subject": null,
                        "fw_interface_from": null,
                        "fw_interface_to": null,
                        "fw_is_phishing": "N/A",
                        "fw_misc": null,
                        "fw_rule": null,
                        "fw_rule_id": null,
                        "fw_serial_number": null,
                        "fw_url_domain": null,
                        "fw_vsys": null,
                        "fw_xff": null,
                        "identity_sub_type": null,
                        "identity_type": null,
                        "image_name": null,
                        "module_id": null,
                        "operation_name": null,
                        "os_actor_causality_id": null,
                        "os_actor_effective_username": null,
                        "os_actor_process_causality_id": null,
                        "os_actor_process_command_line": null,
                        "os_actor_process_image_name": null,
                        "os_actor_process_image_path": null,
                        "os_actor_process_image_sha256": null,
                        "os_actor_process_instance_id": null,
                        "os_actor_process_os_pid": null,
                        "os_actor_process_signature_status": "N/A",
                        "os_actor_process_signature_vendor": null,
                        "os_actor_thread_thread_id": null,
                        "project": null,
                        "referenced_resource": null,
                        "resource_sub_type": null,
                        "resource_type": null,
                        "story_id": null,
                        "user_agent": null,
                        "user_name": null
                    }
                ],
                "external_id": "FAKE-GUID",
                "filter_rule_id": null,
                "host_ip": null,
                "host_name": null,
                "is_pcap": false,
                "is_whitelisted": false,
                "last_modified_ts": 1660240426055,
                "local_insert_ts": 1659455246812,
                "mac": null,
                "mac_addresses": null,
                "matching_service_rule_id": null,
                "matching_status": "MATCHED",
                "mitre_tactic_id_and_name": null,
                "mitre_technique_id_and_name": null,
                "name": "Networking Infrastructure",
                "original_tags": null,
                "resolution_comment": "ASM alert resolution",
                "resolution_status": "STATUS_070_RESOLVED_OTHER",
                "severity": "high",
                "source": "ASM",
                "starred": false,
                "tags": null
            }
        ]
    }
}
```

#### Human Readable Output

>### ASM Alerts
>
>|Action|Action Pretty|Agent Os Type|Alert Id|Alert Type|Description|Detection Timestamp|Events|External Id|Is Pcap|Is Whitelisted|Last Modified Ts|Local Insert Ts|Matching Status|Name|Resolution Comment|Resolution Status|Severity|Source|Starred|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| NOT_AVAILABLE | N/A | NO_HOST | 231 | Unclassified | Networking and security infrastructure, such as firewalls and routers, generally should not have their administration panels open to public Internet. Compromise of these devices, often though password guessing or vulnerability exploitation, provides privileged access to an enterprise network. | 1659452808759 | {'agent_install_type': 'NA', 'agent_host_boot_time': None, 'event_sub_type': None, 'module_id': None, 'association_strength': None, 'dst_association_strength': None, 'story_id': None, 'event_id': None, 'event_type': None, 'event_timestamp': 1659452808759, 'actor_process_instance_id': None, 'actor_process_image_path': None, 'actor_process_image_name': None, 'actor_process_command_line': None, 'actor_process_signature_status': 'N/A', 'actor_process_signature_vendor': None, 'actor_process_image_sha256': None, 'actor_process_image_md5': None, 'actor_process_causality_id': None, 'actor_causality_id': None, 'actor_process_os_pid': None, 'actor_thread_thread_id': None, 'causality_actor_process_image_name': None, 'causality_actor_process_command_line': None, 'causality_actor_process_image_path': None, 'causality_actor_process_signature_vendor': None, 'causality_actor_process_signature_status': 'N/A', 'causality_actor_causality_id': None, 'causality_actor_process_execution_time': None, 'causality_actor_process_image_md5': None, 'causality_actor_process_image_sha256': None, 'action_file_path': None, 'action_file_name': None, 'action_file_md5': None, 'action_file_sha256': None, 'action_file_macro_sha256': None, 'action_registry_data': None, 'action_registry_key_name': None, 'action_registry_value_name': None, 'action_registry_full_key': None, 'action_local_ip': None, 'action_local_ip_v6': None, 'action_local_port': None, 'action_remote_ip': None, 'action_remote_ip_v6': None, 'action_remote_port': 80, 'action_external_hostname': None, 'action_country': 'UNKNOWN', 'action_process_instance_id': None, 'action_process_causality_id': None, 'action_process_image_name': None, 'action_process_image_sha256': None, 'action_process_image_command_line': None, 'action_process_signature_status': 'N/A', 'action_process_signature_vendor': None, 'os_actor_effective_username': None, 'os_actor_process_instance_id': None, 'os_actor_process_image_path': None, 'os_actor_process_image_name': None, 'os_actor_process_command_line': None, 'os_actor_process_signature_status': 'N/A', 'os_actor_process_signature_vendor': None, 'os_actor_process_image_sha256': None, 'os_actor_process_causality_id': None, 'os_actor_causality_id': None, 'os_actor_process_os_pid': None, 'os_actor_thread_thread_id': None, 'fw_app_id': None, 'fw_interface_from': None, 'fw_interface_to': None, 'fw_rule': None, 'fw_rule_id': None, 'fw_device_name': None, 'fw_serial_number': None, 'fw_url_domain': None, 'fw_email_subject': None, 'fw_email_sender': None, 'fw_email_recipient': None, 'fw_app_subcategory': None, 'fw_app_category': None, 'fw_app_technology': None, 'fw_vsys': None, 'fw_xff': None, 'fw_misc': None, 'fw_is_phishing': 'N/A', 'dst_agent_id': None, 'dst_causality_actor_process_execution_time': None, 'dns_query_name': None, 'dst_action_external_hostname': None, 'dst_action_country': None, 'dst_action_external_port': None, 'contains_featured_host': 'NO', 'contains_featured_user': 'NO', 'contains_featured_ip': 'NO', 'image_name': None, 'container_id': None, 'cluster_name': None, 'referenced_resource': None, 'operation_name': None, 'identity_sub_type': None, 'identity_type': None, 'project': None, 'cloud_provider': None, 'resource_type': None, 'resource_sub_type': None, 'user_agent': None, 'user_name': None} | FAKE-GUID | false | false | 1660240725450 | 1659455267908 | MATCHED | Networking Infrastructure | ASM alert resolution | STATUS_070_RESOLVED_OTHER | high | ASM | false |
>| NOT_AVAILABLE | N/A | NO_HOST | 33 | Unclassified | Networking and security infrastructure, such as firewalls and routers, generally should not have their administration panels open to public Internet. Compromise of these devices, often though password guessing or vulnerability exploitation, provides privileged access to an enterprise network. | 1659452809020 | {'agent_install_type': 'NA', 'agent_host_boot_time': None, 'event_sub_type': None, 'module_id': None, 'association_strength': None, 'dst_association_strength': None, 'story_id': None, 'event_id': None, 'event_type': None, 'event_timestamp': 1659452809020, 'actor_process_instance_id': None, 'actor_process_image_path': None, 'actor_process_image_name': None, 'actor_process_command_line': None, 'actor_process_signature_status': 'N/A', 'actor_process_signature_vendor': None, 'actor_process_image_sha256': None, 'actor_process_image_md5': None, 'actor_process_causality_id': None, 'actor_causality_id': None, 'actor_process_os_pid': None, 'actor_thread_thread_id': None, 'causality_actor_process_image_name': None, 'causality_actor_process_command_line': None, 'causality_actor_process_image_path': None, 'causality_actor_process_signature_vendor': None, 'causality_actor_process_signature_status': 'N/A', 'causality_actor_causality_id': None, 'causality_actor_process_execution_time': None, 'causality_actor_process_image_md5': None, 'causality_actor_process_image_sha256': None, 'action_file_path': None, 'action_file_name': None, 'action_file_md5': None, 'action_file_sha256': None, 'action_file_macro_sha256': None, 'action_registry_data': None, 'action_registry_key_name': None, 'action_registry_value_name': None, 'action_registry_full_key': None, 'action_local_ip': None, 'action_local_ip_v6': None, 'action_local_port': None, 'action_remote_ip': None, 'action_remote_ip_v6': None, 'action_remote_port': 80, 'action_external_hostname': None, 'action_country': 'UNKNOWN', 'action_process_instance_id': None, 'action_process_causality_id': None, 'action_process_image_name': None, 'action_process_image_sha256': None, 'action_process_image_command_line': None, 'action_process_signature_status': 'N/A', 'action_process_signature_vendor': None, 'os_actor_effective_username': None, 'os_actor_process_instance_id': None, 'os_actor_process_image_path': None, 'os_actor_process_image_name': None, 'os_actor_process_command_line': None, 'os_actor_process_signature_status': 'N/A', 'os_actor_process_signature_vendor': None, 'os_actor_process_image_sha256': None, 'os_actor_process_causality_id': None, 'os_actor_causality_id': None, 'os_actor_process_os_pid': None, 'os_actor_thread_thread_id': None, 'fw_app_id': None, 'fw_interface_from': None, 'fw_interface_to': None, 'fw_rule': None, 'fw_rule_id': None, 'fw_device_name': None, 'fw_serial_number': None, 'fw_url_domain': None, 'fw_email_subject': None, 'fw_email_sender': None, 'fw_email_recipient': None, 'fw_app_subcategory': None, 'fw_app_category': None, 'fw_app_technology': None, 'fw_vsys': None, 'fw_xff': None, 'fw_misc': None, 'fw_is_phishing': 'N/A', 'dst_agent_id': None, 'dst_causality_actor_process_execution_time': None, 'dns_query_name': None, 'dst_action_external_hostname': None, 'dst_action_country': None, 'dst_action_external_port': None, 'contains_featured_host': 'NO', 'contains_featured_user': 'NO', 'contains_featured_ip': 'NO', 'image_name': None, 'container_id': None, 'cluster_name': None, 'referenced_resource': None, 'operation_name': None, 'identity_sub_type': None, 'identity_type': None, 'project': None, 'cloud_provider': None, 'resource_type': None, 'resource_sub_type': None, 'user_agent': None, 'user_name': None} | FAKE-GUID | false | false | 1660240426055 | 1659455246812 | MATCHED | Networking Infrastructure | ASM alert resolution | STATUS_070_RESOLVED_OTHER | high | ASM | false |


### asm-get-attack-surface-rule

***
Fetches attack surface rules related to how Cortex Xpanse does assessment.

#### Base Command

`asm-get-attack-surface-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enabled_status | Enablement status to search rules with. Valid values are  "On" and "Off". | Optional | 
| category | Comma-separated list of strings attack surface rule categories. | Optional | 
| priority | Comma-separated list of strings attack surface rule priorities. | Optional | 
| attack_surface_rule_ids | Comma-separated list of strings attack surface rule IDs. | Optional | 
| limit | Maximum number of results to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.AttackSurfaceRules.priority | unknown | Priority level for the different rules. Low, Medium, High, Critical. | 
| ASM.AttackSurfaceRules.attack_surface_rule_name | unknown | Name of the attack surface rule. | 
| ASM.AttackSurfaceRules.attack_surface_rule_id | unknown | ID of the attack surface rule. | 
| ASM.AttackSurfaceRules.description | unknown | Description of the attack surface rule. | 
| ASM.AttackSurfaceRules.category | unknown | Category of the attack surface rule. | 
| ASM.AttackSurfaceRules.remediation_guidance | unknown | Guidance for how to address various ASM risks. | 
| ASM.AttackSurfaceRules.enabled_status | unknown | Enablement status of the attack surface rule. | 
| ASM.AttackSurfaceRules.created | unknown | Creation date of the attack surface rule. | 
| ASM.AttackSurfaceRules.modified | unknown | Last modification of the attack surface rule. | 

#### Command example

```!asm-get-attack-surface-rule enabled_status=On limit=1```

#### Context Example

```json
{
    "ASM": {
        "AttackSurfaceRules": {
            "attack_surface_rule_id": "VMwareVRealizeAutomationAppliance",
            "attack_surface_rule_name": "VMware vRealize Automation Appliance",
            "category": "Attack Surface Reduction",
            "created": 1688836450000,
            "description": "VMware vRealize Automation, formerly vCloud Automation Center, is a software product that offers multivendor and multicloud support. It allows for IT infrastructure personalization and resource provisioning and configuration, and it automates application delivery and container management. This issue identifies the web login interface for VMware vRealize Automation Appliance.",
            "enabled_status": "On",
            "knowledge_base_link": null,
            "modified": 1688074708000,
            "modified_by": null,
            "priority": "High",
            "remediation_guidance": "Due to the network access provided by VMware vRealize Automation, it is recommended for instances of VMware vRealize Automation to not be accessible to the public Internet unless there is a business need.\nXpanse recommends working to identify the asset owner and collaborating with them to remove the asset from the internet."
        }
    }
}
```

#### Human Readable Output

>### Attack Surface Rules
>
>|Attack Surface Rule Id|Attack Surface Rule Name|Category|Created|Description|Enabled Status|Modified|Priority|Remediation Guidance|
>|---|---|---|---|---|---|---|---|---|
>| VMwareVRealizeAutomationAppliance | VMware vRealize Automation Appliance | Attack Surface Reduction | 1688836450000 | VMware vRealize Automation, formerly vCloud Automation Center, is a software product that offers multivendor and multicloud support. It allows for IT infrastructure personalization and resource provisioning and configuration, and it automates application delivery and container management. This issue identifies the web login interface for VMware vRealize Automation Appliance. | On | 1688074708000 | High | Due to the network access provided by VMware vRealize Automation, it is recommended for instances of VMware vRealize Automation to not be accessible to the public Internet unless there is a business need.<br>Xpanse recommends working to identify the asset owner and collaborating with them to remove the asset from the internet. |

### asm-tag-asset-assign

***
Assigns tags to a list of assets.

#### Base Command

`asm-tag-asset-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_id_list | Comma-separated list of asset IDs to add tags to. | Required | 
| tags | The name of the tags to apply to supplied assets. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!asm-tag-asset-assign tags="Test" asm_id_list="76fb0c06-52cf-33b5-8166-3a130bb25eb6"```

#### Context Example

```json
{
    "ASM": {
        "TagAssignment": "Assignment operation: succeeded"
    }
}
```

#### Human Readable Output

```Assignment operation: succeeded```

### asm-tag-asset-remove

***
Removes tags from a list of assets.

#### Base Command

`asm-tag-asset-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_id_list | Comma-separated list of asset IDs to remove tags from. | Optional | 
| tags | The name of the tags to remove from supplied assets. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!asm-tag-asset-remove tags="Test" asm_id_list="76fb0c06-52cf-33b5-8166-3a130bb25eb6"```

#### Context Example

```json
{
    "ASM": {
        "TagRemoval": "Removal operation: succeeded"
    }
}
```

#### Human Readable Output

```Removal operation: succeeded```

### asm-tag-range-assign

***
Assigns tags to a list of IP ranges.

#### Base Command

`asm-tag-range-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id_list | Comma-separated list of range IDs to add tags to. | Optional | 
| tags | The name of the tags to apply to supplied assets. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!asm-tag-range-assign range_id_list="ba8d8f59-6445-37c0-a145-2233f9e5a9bd" tags="Test"```

#### Context Example

```json
{
    "ASM": {
        "TagAssignment": "Assignment operation: succeeded"
    }
}
```

#### Human Readable Output

```Assignment operation: succeeded```

### asm-tag-range-remove

***
Removes tags from a list of IP ranges.

#### Base Command

`asm-tag-range-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id_list | Comma-separated list of range IDs to remove tags from. | Optional | 
| tags | The name of the tags to remove from supplied IP ranges. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!asm-tag-range-remove range_id_list="ba8d8f59-6445-37c0-a145-2233f9e5a9bd" tags="Test"```

#### Context Example

```json
{
    "ASM": {
        "TagRemoval": "Removal operation: succeeded"
    }
}
```

#### Human Readable Output

```Removal operation: succeeded```

### asm-list-incidents

***
Fetches ASM incidents that match provided filters. Incidents are an aggregation of related alerts. Note: Incident IDs may also be references as "Case IDs' elsewhere in the API.

#### Base Command

`asm-list-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id_list | Incident IDs to filter on. Note: Incident IDs may also be references as "Case IDs' elsewhere in the API. | Optional | 
| description | String to search for within the incident description field. | Optional | 
| status | Status to search incidents for. Possible values are: new, under_investigation, resolved. | Optional | 
| lte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or before the specified date/time will be retrieved. | Optional | 
| gte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or after the specified date/time will be retrieved. | Optional | 
| sort_by_creation_time | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). | Optional | 
| sort_by_severity | Sorts returned incidents by the severity of the incident. | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). | Optional | 
| limit | Maximum number of incidents to return per page. The default and maximum is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.Incident.alert_count | Number | Number of alerts included in the incident. | 
| ASM.Incident.alerts_grouping_status | String | Whether alert grouping is enabled. | 
| ASM.Incident.assigned_user_mail | Unknown | Email of the assigned user. | 
| ASM.Incident.assigned_user_pretty_name | Unknown | Friendly name of the assigned user. | 
| ASM.Incident.creation_time | Date | Creation timestamp. | 
| ASM.Incident.critical_severity_alert_count | Number | Number of critical alerts. | 
| ASM.Incident.description | String | Description of the incident. | 
| ASM.Incident.high_severity_alert_count | Number | Number of high alerts. | 
| ASM.Incident.incident_id | String | ID of the incident. | 
| ASM.Incident.incident_name | Unknown | Incident name. | 
| ASM.Incident.incident_sources | String | Incident source. | 
| ASM.Incident.low_severity_alert_count | Number | Number of low alerts. | 
| ASM.Incident.manual_severity | Unknown | Severity override. | 
| ASM.Incident.med_severity_alert_count | Number | Number of medium alerts. | 
| ASM.Incident.modification_time | Date | Modification timestamp. | 
| ASM.Incident.notes | Unknown | Incident notes. | 
| ASM.Incident.original_tags | Unknown | Tags on the incident at creation time. | 
| ASM.Incident.resolve_comment | Unknown | Resolution comment \(optional\). | 
| ASM.Incident.resolved_timestamp | Unknown | Resolution timestamp. | 
| ASM.Incident.severity | String | Severity of the incident. | 
| ASM.Incident.starred | Boolean | Whether the incident has been starred. | 
| ASM.Incident.status | String | Status of the incident. | 
| ASM.Incident.tags | String | Tags on the incident. | 
| ASM.Incident.xdr_url | String | Link to navigate to the incident. | 
| ASM.Incident.xpanse_risk_score | Unknown | Risk score of the incident. | 

#### Command example

```!asm-list-incidents limit=1 status=new```

#### Context Example

```json
{
    "ASM": {
        "Incident": {
            "aggregated_score": null,
            "alert_categories": null,
            "alert_count": 1,
            "alerts_grouping_status": "Enabled",
            "assigned_user_mail": null,
            "assigned_user_pretty_name": null,
            "creation_time": 1688837015292,
            "critical_severity_alert_count": 0,
            "description": "'Insecure Communication Protocol at example.com:443'",
            "detection_time": null,
            "high_severity_alert_count": 0,
            "host_count": 1,
            "hosts": [
                "1.1.1.1:null"
            ],
            "incident_id": "5508",
            "incident_name": null,
            "incident_sources": [
                "ASM"
            ],
            "low_severity_alert_count": 0,
            "manual_description": null,
            "manual_score": null,
            "manual_severity": null,
            "med_severity_alert_count": 1,
            "modification_time": 1688837015292,
            "notes": null,
            "original_tags": [],
            "resolve_comment": null,
            "resolved_timestamp": null,
            "rule_based_score": null,
            "severity": "medium",
            "starred": false,
            "status": "new",
            "tags": [
                "AR:Registered to You",
                "IPR:Test IP"
            ],
            "user_count": 0,
            "xdr_url": "https://exp-test.crtx.eu.paloaltonetworks.com/incident-view?caseId=5508",
            "xpanse_risk_score": null
        }
    }
}
```

#### Human Readable Output
>
>### ASM Incidents
>
>|Alert Count|Alerts Grouping Status|Creation Time|Critical Severity Alert Count|Description|High Severity Alert Count|Host Count| Hosts        |Incident Id|Incident Sources|Low Severity Alert Count|Med Severity Alert Count|Modification Time|Severity|Starred|Status|Tags|User Count|Xdr Url|
>|---|---|---|---|---|---|---|--------------|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | Enabled | 1688837015292 | 0 | 'Insecure Communication Protocol at example.com:443' | 0 | 1 | 1.1.1.1:null | 5508 | ASM | 0 | 1 | 1688837015292 | medium | false | new | AR:Registered to You,<br>IPR:Test IP | 0 | https://exp-test.crtx.eu.paloaltonetworks.com/incident-view?caseId=5508 |

### asm-get-incident

***
Returns additional details about a specific incident. Note: Incident IDs may also be references as "Case IDs" elsewhere in the API.

#### Base Command

`asm-get-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- |--------------|
| incident_id | The ID of the incident to be fetched. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- |----------| --- |
| ASM.Incident.incident_id | String   | The ID of the incident. | 
| ASM.Incident.xpanse_risk_score | Number   | The Xpanse risk score of the incident. | 
| ASM.Incident.alerts | Unknown  | The alerts included in the incident. | 
| ASM.Incident.tags | Unknown  | Tags assigned to assets included in the incident. | 
| ASM.Incident.status | String   | The status of the incident. | 
| ASM.Incident.severity | String   | The severity of the incident. | 
| ASM.Incident.description | String   | Description of the incident. | 
| ASM.Incident.notes | String   | User-provided notes related to the incident. | 

#### Command example

```!asm-get-incident incident_id=71```

#### Context Example

```json
{
  "aggregated_score": 825,
  "alert_categories": null,
  "alert_count": 2,
  "alerts": [
    {
      "alert_id": "113716",
      "description": "This issue flags on-premises Microsoft Exchange Servers that are known to be below the current up-to-date secured versions suggested by Microsoft.",
      "name": "Insecure Microsoft Exchange Server (15.0.1497.36) at 1.1.1.1:443",
      "resolution_status": "STATUS_020_UNDER_INVESTIGATION"
    },
    {
      "alert_id": "89896",
      "description": "The X-XSS-Protection header is used to reduce the risk of cross-site scripting attacks. Not including it could make your website less secure.",
      "name": "Missing X-Xss-Protection at 1.1.1.1:443",
      "resolution_status": "STATUS_010_NEW"
    }
  ],
  "alerts_grouping_status": "Disabled",
  "assigned_user_mail": "cs@acme.com",
  "assigned_user_pretty_name": "User One",
  "creation_time": 1671912678672,
  "critical_severity_alert_count": 0,
  "description": "'Insecure Microsoft Exchange Server (15.0.1497.36) at 1.1.1.1:443' along with 1 other alerts",
  "detection_time": null,
  "high_severity_alert_count": 4,
  "host_count": 1,
  "hosts": [
    "1.1.1.1:null"
  ],
  "incident_id": "71",
  "incident_name": null,
  "incident_sources": [
    "ASM"
  ],
  "is_blocked": false,
  "low_severity_alert_count": 0,
  "manual_description": null,
  "manual_score": null,
  "manual_severity": null,
  "med_severity_alert_count": 2,
  "modification_time": 1696275576460,
  "notes": null,
  "original_tags": [
    "BU:Xpanse VanDelay Demo 3"
  ],
  "resolve_comment": null,
  "resolved_timestamp": null,
  "rule_based_score": 825,
  "severity": "high",
  "starred": true,
  "status": "under_investigation",
  "tags": [
    "AR:Registered to You"
  ],
  "user_count": 0,
  "xdr_url": "https://exp-test.crtx.eu.paloaltonetworks.com/incident-view?caseId=71",
  "xpanse_risk_explainer": {
    "cves": [
      {
        "confidence": "High",
        "cveId": "CVE-2021-26855",
        "cvssScore": 9.800000190734863,
        "epssScore": 0.9749900102615356,
        "exploitMaturity": "Weaponized",
        "matchType": "ExactVersionMatch",
        "mostRecentReportedExploitDate": "2023-10-12",
        "reportedExploitInTheWild": true
      },
      {
        "confidence": "High",
        "cveId": "CVE-2021-34473",
        "cvssScore": 9.800000190734863,
        "epssScore": 0.9732999801635742,
        "exploitMaturity": "Weaponized",
        "matchType": "ExactVersionMatch",
        "mostRecentReportedExploitDate": "2023-10-12",
        "reportedExploitInTheWild": true
      },
      {
        "confidence": "High",
        "cveId": "CVE-2021-34523",
        "cvssScore": 9.800000190734863,
        "epssScore": 0.9726300239562988,
        "exploitMaturity": "Weaponized",
        "matchType": "ExactVersionMatch",
        "mostRecentReportedExploitDate": "2023-10-12",
        "reportedExploitInTheWild": true
      }
    ],
    "riskFactors": [
      {
        "attributeId": "misconfiguration",
        "attributeName": "Misconfiguration",
        "issueTypes": [
          {
            "displayName": "Insecure Microsoft Exchange Server",
            "issueTypeId": "InsecureMicrosoftExchangeServer"
          },
          {
            "displayName": "Missing X-XSS-Protection Header",
            "issueTypeId": "MissingXXssProtectionHeader"
          }
        ]
      },
      {
        "attributeId": "critical_system",
        "attributeName": "Critical System",
        "issueTypes": [
          {
            "displayName": "Insecure Microsoft Exchange Server",
            "issueTypeId": "InsecureMicrosoftExchangeServer"
          }
        ]
      },
      {
        "attributeId": "potential_data_loss",
        "attributeName": "Potential Data Loss",
        "issueTypes": [
          {
            "displayName": "Insecure Microsoft Exchange Server",
            "issueTypeId": "InsecureMicrosoftExchangeServer"
          }
        ]
      }
    ],
    "versionMatched": true
  },
  "xpanse_risk_score": 825
}
```

#### Human Readable Output
>
>### ASM Incident
>
>|Aggregated Score| Alert Count | Alerts                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |Alerts Grouping Status|Assigned User Mail| Assigned User Pretty Name |Creation Time|Critical Severity Alert Count| Description                                                                                  |High Severity Alert Count|Host Count| Hosts        |Incident Id|Incident Sources|Is Blocked|Low Severity Alert Count|Med Severity Alert Count|Modification Time|Original Tags|Rule Based Score|Severity|Starred|Status|Tags|User Count|Xdr Url|Xpanse Risk Explainer|Xpanse Risk Score|
>|---|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---|---|---------------------------|---|---|----------------------------------------------------------------------------------------------|---|---|--------------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 825 | 2           | {'alert_id': '113716', 'name': 'Insecure Microsoft Exchange Server (15.0.1497.36) at 1.1.1.1:443', 'description': 'This issue flags on-premises Microsoft Exchange Servers that are known to be below the current up-to-date secured versions suggested by Microsoft.' , 'resolution_status': 'STATUS_010_NEW'},<br>{'alert_id': '89896', 'name': 'Missing X-Xss-Protection at 1.1.1.1:443', 'description': 'The X-XSS-Protection header is used to reduce the risk of cross-site scripting attacks. Not including it could make your website less secure.', 'resolution_status': 'STATUS_010_NEW'} | Disabled | cs@acme.com | User One                  | 1671912678672 | 0 | 'Insecure Microsoft Exchange Server (15.0.1497.36) at 1.1.1.1:443' along with 1 other alerts | 4 | 1 | 1.1.1.1:null | 71 | ASM | false | 0 | 2 | 1696275576460 | BU:Xpanse VanDelay Demo 3 | 825 | high | true | under_investigation | AR:Registered to You | 0 | https://exp-test.crtx.eu.paloaltonetworks.com/incident-view?caseId=71 | cves: {'cveId': 'CVE-2021-26855', 'cvssScore': 9.800000190734863, 'epssScore': 0.9749900102615356, 'matchType': 'ExactVersionMatch', 'confidence': 'High', 'exploitMaturity': 'Weaponized', 'reportedExploitInTheWild': True, 'mostRecentReportedExploitDate': '2023-10-12'},<br>{'cveId': 'CVE-2021-34473', 'cvssScore': 9.800000190734863, 'epssScore': 0.9732999801635742, 'matchType': 'ExactVersionMatch', 'confidence': 'High', 'exploitMaturity': 'Weaponized', 'reportedExploitInTheWild': True, 'mostRecentReportedExploitDate': '2023-10-12'},<br>{'cveId': 'CVE-2021-34523', 'cvssScore': 9.800000190734863, 'epssScore': 0.9726300239562988, 'matchType': 'ExactVersionMatch', 'confidence': 'High', 'exploitMaturity': 'Weaponized', 'reportedExploitInTheWild': True, 'mostRecentReportedExploitDate': '2023-10-12'}<br>riskFactors: {'attributeId': 'misconfiguration', 'attributeName': 'Misconfiguration', 'issueTypes': [{'displayName': 'Insecure Microsoft Exchange Server', 'issueTypeId': 'InsecureMicrosoftExchangeServer'}, {'displayName': 'Missing X-XSS-Protection Header', 'issueTypeId': 'MissingXXssProtectionHeader'}]},<br>{'attributeId': 'critical_system', 'attributeName': 'Critical System', 'issueTypes': [{'displayName': 'Insecure Microsoft Exchange Server', 'issueTypeId': 'InsecureMicrosoftExchangeServer'}]},<br>{'attributeId': 'potential_data_loss', 'attributeName': 'Potential Data Loss', 'issueTypes': [{'displayName': 'Insecure Microsoft Exchange Server', 'issueTypeId': 'InsecureMicrosoftExchangeServer'}]}<br>versionMatched: true | 825 |

### asm-update-incident

***
Updates a given incident. Can be used to modify the status, severity, assignee, or add comments.

#### Base Command

`asm-update-incident`

#### Input

| **Argument Name** | **Description**                                                                                      | **Required** |
| --- |------------------------------------------------------------------------------------------------------| --- |
| incident_id | ID of the incident to modify.                                                                        | Required | 
| alert_id | Used for scoping updates such as comments to the alert level.                                        | Optional | 
| assigned_user_mail | Email address of the user to assign incident to. This user must exist within your Expander instance. | Optional | 
| manual_severity | Administrator-defined severity for the incident.                                                     | Optional | 
| status | Incident status. Possible values are: new, under_investigation, resolved.                            | Optional | 
| resolve_comment | Optional resolution comment when resolving the incident.                                             | Optional | 
| comment | A comment to add to the incident. If an alert_id is supplied it will be prefixed to the comment.     | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.IncidentUpdate | unknown | Whether the incident update was successful. | 


#### Command example

```!asm-update-incident incident_id="3674" alert_id="4372" comment="this is an xsoar test"```

#### Context Example

```json
{
    "ASM": {
        "IncidentUpdate": "Update operation successful: true"
    }
}
```

#### Human Readable Output

```Update operation successful: true```


### asm-update-alerts

***
Updates the state of one or more alerts.

#### Base Command

`asm-update-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id_list | Comma-separated list of integers of the alert ID. | Optional | 
| status | Updated alert status. Possible values are: new, reopened, under_investigation, resolved_no_longer_observed, resolved_no_risk, resolved_risk_accepted, resolved_contested_asset, resolved_remediated_automatically, resolved. | Optional | 
| severity | The severity of the alert. Possible values are: low, medium, high, critical. | Optional | 
| resolution_comment | Descriptive comment explaining the alert change. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.UpdatedAlerts | unknown | IDs of the updated alerts. |

#### Command example

```!asm-update-alerts alert_id_list=602 status=new```

#### Context Example

```json
{
    "ASM": {
        "UpdatedAlerts": [602]
    }
}
```

#### Human Readable Output

```Updated alerts: [602]```

### ip

***
(Deprecated as of version 1.2.7) Returns reputation lookup for an IP address found in Xpanse.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description**       | **Required** |
|-------------------|-----------------------|--------------|
| ip                | IP address to enrich. | Required     | 

#### Context Output

| **Path**                  | **Type** | **Description**                                                            |
|---------------------------|----------|----------------------------------------------------------------------------|
| ASM.IP.ip                 | String   | The IP address of the asset.                                               |
| ASM.IP.domain             | String   | The domain affiliated with an asset.                                       |
| ASM.IP.name               | String   | The asset name.                                                            |
| ASM.IP.asset_type         | String   | The asset type.                                                            |
| ASM.IP.first_observed     | unknown  | When the asset was first observed.                                         |
| ASM.IP.last_observed      | unknown  | When the asset was last observed.                                          |
| ASM.IP.asm_ids            | unknown  | The ID of the asset.                                                       |
| ASM.IP.service_type       | unknown  | Affiliated service types for the asset.                                    |
| ASM.IP.tags               | unknown  | A list of tags that have been assigned to the asset.                       |
| ASM.IP.asset_explainers   | unknown  | The asset explanation details.                                             |
| ASM.IP.domain_details     | unknown  | Additional domain details.                                                 |
| ASM.IP.recent_ips         | unknown  | Details about the recent IP observations.                                  |
| DBotScore.Vendor          | String   | The vendor reporting the score of the indicator.                           |
| DBotScore.Score           | Integer  | An integer regarding the status of the indicator.                          |
| DBotScore.Indicator       | String   | The indicator value.                                                       |
| DBotScore.Type            | String   | The vendor used to calculate the score.                                    |
| DBotScore.Reliability     | String   | Reliability of the source providing the intelligence data.                 |
| IP.Address                | String   | IP address.                                                                |
| ASM.TIM.IP.name           | String   | The existing Cortex Xpanse IP address recently updated in the Cortex XSOAR indicators        |
| ASM.TIM.IP.indicator_type | String   | The existing Cortex Xpanse indicator type in the Cortex XSOAR indicators                     |
| ASM.TIM.IP.id             | String   | The existing indicator ID in the Cortex XSOAR indicators                              |
| ASM.TIM.IP.reliability    | String   | The existing indicator reliability recently updated in the Cortex XSOAR indicators    |
| ASM.TIM.IP.score          | Integer  | The existing indicator score recently updated in the Cortex XSOAR indicators          |


#### Command example

```!ip ip='1.1.1.1, 1.1.1.2, 8.8.8.8'```

#### Context Example

If the indicator was **not** updated in Cortex XSOAR in the last 3 days:

```json
{
    "ASM": {
        "IP": {
            "asm_ids": [
                "4b1f3765-de40-3a1a-8535-667420408fd9"
            ],
            "asset_explainers": [],
            "asset_type": "DOMAIN",
            "domain": "*.acme.com",
            "domain_details": {
                "admin": {
                    "city": "",
                    "country": "us",
                    "emailAddress": "",
                    "faxExtension": null,
                    "faxNumber": "",
                    "name": "",
                    "organization": "Acme, Inc.",
                    "phoneExtension": null,
                    "phoneNumber": "",
                    "postalCode": "",
                    "province": "AZ",
                    "registryId": null,
                    "street": ""
                },
                "alignedRegistrar": "MarkMonitor",
                "collectionTime": 1695942091000,
                "creationDate": 785376000000,
                "dnssec": null,
                "domainName": "acme.com",
                "domainStatuses": [
                    "clientUpdateProhibited",
                    "clientTransferProhibited",
                    "clientDeleteProhibited"
                ],
                "dropped": false,
                "nameServers": []
            },
            "first_observed": 1679457579382,
            "ip": "1.1.1.1",
            "last_observed": 1697361335282,
            "name": "*.acme.com",
            "recent_ips": [
                {
                    "firstObserved": 1692418207732,
                    "id": "218b3cc9-2d26-3a17-aadd-9eac08cc30ec",
                    "ip": "1.1.1.1",
                    "ipv6": null,
                    "lastObserved": 1697361335282,
                    "provider": {
                        "additionalProviderInfo": null,
                        "cdn": false,
                        "displayName": "Amazon Web Services",
                        "isCdn": false,
                        "legacyName": "AWS",
                        "name": "AWS"
                    },
                    "source": {
                        "name": "DOMAIN_RESOLUTION"
                    }
                }
            ],
            "service_type": [
                "HttpServer"
            ],
            "tags": [
                "BU:Xpanse VanDelay Demo 3"
            ]
        }
    }
}
```

If the indicator is **related to Xpanse** was updated in Cortex XSOAR in the last 3 days:

```json
{
    "ASM": {
        "TIM": {
            "id": "abcd1b2abcd1a0b20c7a8bc5d67e8eea",
            "indicator_type": "IP",
            "name": "1.1.1.2",
            "reliability": "A+ - 3rd party enrichment",
            "score": 0
        }
    }
}
```

#### Human Readable Output

If the indicator was **not** updated in Cortex XSOAR in the last 3 days:

> ### Xpanse Discovered IP List
>
> |asm_ids|asset_explainers|asset_type|domain|domain_details|first_observed|ip|last_observed|name|recent_ips|service_type|tags|
> |---|---|---|---|---|---|---|---|---|---|---|---|
> | 4b1f3765-de40-3a1a-8535-667420408fd9 |  | DOMAIN | *.acme.com | admin: {"city": "", "country": "us", "emailAddress": "", "faxExtension": null, "faxNumber": "", "name": "", "organization": "Acme, Inc.", "phoneExtension": null, "phoneNumber": "", "postalCode": "", "province": "AZ", "registryId": null, "street": ""}| 1679457579382 | 1.1.1.1 | 1697361335282 | *.acme.com | {'id': '218b3cc9-2d26-3a17-aadd-9eac08cc30ec', 'ip': 52529952, 'ipv6': None, 'source': {'name': 'DOMAIN_RESOLUTION'}, 'provider': {'name': 'AWS', 'additionalProviderInfo': None, 'isCdn': False, 'legacyName': 'AWS', 'displayName': 'Amazon Web Services', 'cdn': False}, 'firstObserved': 1692418207732, 'lastObserved': 1697361335282} | HttpServer | BU:Xpanse VanDelay Demo 3 |

If the indicator is **related to Xpanse** was updated in Cortex XSOAR in the last 3 days:

> ### Xpanse Discovered IP List (Existing Indicators)
>
> This domain list is from existing records found in Cortex XSOAR within the last 3 days.
> If you would additional Cortex Xpanse specific information about these, use asm-list-asset-internet-exposure.
>
> |id|indicator_type|name|reliability|score|
> |---|---|---|---|---|
> | abcd1b2abcd1a0b20c7a8bc5d67e8eea | IP | 1.1.1.2 | A+ - 3rd party enrichment | 0 |

If the indicator was updated in Cortex XSOAR in the last 3 days:

> ### XSOAR Indicator Discovered IP List (Not Related to Cortex Xpanse)
> 
> This IP list is from existing records found in Cortex XSOAR within the last 3 days.
> These IPs have not been found to be attributed to Cortex Xpanse.
> 
> |integrations|name|
> |---|---|
> | VirusTotal (API v3) | 8.8.8.8 |


### domain

***
(Deprecated as of version 1.2.7) Returns reputation lookup for an domain found in Cortex Xpanse.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description**   | **Required** |
|-------------------|-------------------|--------------|
| domain            | Domain to enrich. | Required     | 

#### Context Output

| **Path**                      | **Type** | **Description**                                                            |
|-------------------------------|----------|----------------------------------------------------------------------------|
| ASM.Domain.domain             | String   | The domain affiliated with an asset.                                       |
| ASM.Domain.name               | String   | The asset name.                                                            |
| ASM.Domain.asset_type         | String   | The asset type.                                                            |
| ASM.Domain.first_observed     | unknown  | When the asset was first observed.                                         |
| ASM.Domain.last_observed      | unknown  | When the asset was last observed.                                          |
| ASM.Domain.asm_ids            | unknown  | The ID of the asset.                                                       |
| ASM.Domain.service_type       | unknown  | Affiliated service types for the asset.                                    |
| ASM.Domain.tags               | unknown  | A list of tags that have been assigned to the asset.                       |
| ASM.Domain.asset_explainers   | unknown  | The asset explanation details.                                             |
| ASM.Domain.domain_details     | unknown  | Additional domain details.                                                 |
| ASM.Domain.recent_ips         | unknown  | Details about the recent IP observations.                                  |
| DBotScore.Vendor              | String   | The vendor reporting the score of the indicator.                           |
| DBotScore.Score               | Number   | An integer regarding the status of the indicator.                          |
| DBotScore.Indicator           | String   | The indicator value.                                                       |
| DBotScore.Type                | String   | The vendor used to calculate the score.                                    |
| DBotScore.Reliability         | String   | Reliability of the source providing the intelligence data.                 |
| Domain.Name                   | String   | Name of the domain.                                                        |
| ASM.TIM.Domain.name           | String   | The existing Cortex Xpanse domain recently updated in the Cortex XSOAR indicators            |
| ASM.TIM.Domain.indicator_type | String   | The existing Cortex Xpanse indicator type in the Cortex XSOAR indicators                     |
| ASM.TIM.Domain.id             | String   | The existing indicator ID in the Cortex XSOAR indicators                              |
| ASM.TIM.Domain.reliability    | String   | The existing indicator reliability recently updated in the Cortex XSOAR indicators    |
| ASM.TIM.Domain.score          | Integer  | The existing indicator score recently updated in the Cortex XSOAR indicators          |

#### Command example

```!domain domain="*.acme.com, www.example.com, www.fakedomain.com"```

#### Context Example

If the indicator was **not** updated in Cortex XSOAR in the last 3 days:

```json
{
    "ASM": {
        "Domain": {
            "asm_ids": [
                "4b1f3765-de40-3a1a-8535-667420408fd9"
            ],
            "asset_explainers": [],
            "asset_type": "DOMAIN",
            "domain": "*.acme.com",
            "domain_details": {
                "admin": {
                    "city": "",
                    "country": "us",
                    "emailAddress": "",
                    "faxExtension": null,
                    "faxNumber": "",
                    "name": "",
                    "organization": "Acme, Inc.",
                    "phoneExtension": null,
                    "phoneNumber": "",
                    "postalCode": "",
                    "province": "AZ",
                    "registryId": null,
                    "street": ""
                },
                "alignedRegistrar": "MarkMonitor",
                "collectionTime": 1695942091000,
                "creationDate": 785376000000,
                "dnssec": null,
                "domainName": "acme.com",
                "domainStatuses": [
                    "clientUpdateProhibited",
                    "clientTransferProhibited",
                    "clientDeleteProhibited"
                ],
                "dropped": false,
                "nameServers": []
            },
            "first_observed": 1679457579382,
            "last_observed": 1697361335282,
            "name": "*.acme.com",
            "recent_ips": [
                {
                    "firstObserved": 1692418207732,
                    "id": "218b3cc9-2d26-3a17-aadd-9eac08cc30ec",
                    "ip": "1.1.1.1",
                    "ipv6": null,
                    "lastObserved": 1697361335282,
                    "provider": {
                        "additionalProviderInfo": null,
                        "cdn": false,
                        "displayName": "Amazon Web Services",
                        "isCdn": false,
                        "legacyName": "AWS",
                        "name": "AWS"
                    },
                    "source": {
                        "name": "DOMAIN_RESOLUTION"
                    }
                }
            ],
            "service_type": [
                "HttpServer"
            ],
            "tags": [
                "BU:Xpanse VanDelay Demo 3"
            ]
        }
    }
}
```

If the indicator is **related to Xpanse** was updated in Cortex XSOAR in the last 3 days:

```json
{
    "ASM": {
        "TIM": {
            "id": "abcd1b2abcd1a0b20c7a8bc5d67e8eea",
            "indicator_type": "Domain",
            "name": "www.example.com",
            "reliability": "A+ - 3rd party enrichment",
            "score": 0
        }
    }
}
```

#### Human Readable Output

If the indicator was **not** updated in Cortex XSOAR in the last 3 days:

> ### Xpanse Discovered Domain List
>
> |asm_ids|asset_explainers|asset_type|domain|domain_details|first_observed|last_observed|name|recent_ips|service_type|tags|
> |---|---|---|---|---|---|---|---|---|---|---|---|
> | 4b1f3765-de40-3a1a-8535-667420408fd9 |  | DOMAIN | *.acme.com | admin: {"city": "", "country": "us", "emailAddress": "", "faxExtension": null, "faxNumber": "", "name": "", "organization": "Acme, Inc.", "phoneExtension": null, "phoneNumber": "", "postalCode": "", "province": "AZ", "registryId": null, "street": ""}| 1679457579382 | 1697361335282 | *.acme.com | {'id': '218b3cc9-2d26-3a17-aadd-9eac08cc30ec', 'ip': 52529952, 'ipv6': None, 'source': {'name': 'DOMAIN_RESOLUTION'}, 'provider': {'name': 'AWS', 'additionalProviderInfo': None, 'isCdn': False, 'legacyName': 'AWS', 'displayName': 'Amazon Web Services', 'cdn': False}, 'firstObserved': 1692418207732, 'lastObserved': 1697361335282} | HttpServer | BU:Xpanse VanDelay Demo 3 |

If the indicator is **related to Xpanse** was updated in Cortex XSOAR in the last 3 days:

> ### Xpanse Discovered Domain List (Existing Indicators)
>
> This domain list is from existing records found in Cortex XSOAR within the last 3 days.
> If you would like additional Cortex Xpanse specific information about these, use asm-list-asset-internet-exposure.
>
> |id|indicator_type|name|reliability|score|
> |---|---|---|---|---|
> | abcd1b2abcd1a0b20c7a8bc5d67e8eea | Domain | www.example.com | A+ - 3rd party enrichment | 0 |

If the indicator was updated in Cortex XSOAR in the last 3 days:

> ### XSOAR Indicator Discovered Domain List (Not Related to Xpanse)
> 
> This domain list is from existing records found in Cortex XSOAR within the last 3 days.
> These domains have not been found to be attributed to Cortex Xpanse.
> |integrations|name|
> |---|---|
> | VirusTotal (API v3) | www.fakedomain.com |


### asm-list-external-websites

***
Get a list of all your external websites filtered by authentication type. Maximum result limit is 500 assets.

#### Base Command

`asm-list-external-website`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| authentication | Authentication type string on which to search. | Optional | 
| limit | Maximum number of assets to return. The default and maximum is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.Externalwebsite.website_id | String | External website UUID. | 
| ASM.Externalwebsite.website_name | String | Name of the external website. | 
| ASM.Externalwebsite.website_type | String | Type of the external website. | 
| ASM.Externalwebsite.ip_address | String | IP address of the external website. | 
| ASM.Externalwebsite.externally_detected_providers | String | Providers of external website. | 
| ASM.Externalwebsite.is_active | String | Whether the external website is active. | 
| ASM.Externalwebsite.first_observed | Date | Date of the first observation of the external website. | 
| ASM.Externalwebsite.last_observed | Date | Date of the last observation of the external website. | 
| ASM.Externalwebsite.port | Number | Port number of the external website. | 
| ASM.Externalwebsite.protocol | String | Protocol number of the external website. | 
| ASM.Externalwebsite.inactive_classifications | String | External website classifications that are no longer active. | 
| ASM.Externalwebsite.discovery_type | String | How the external website was discovered. | 
| ASM.Externalwebsite.business_units | String | External website associated business units. | 
| ASM.Externalwebsite.externally_inferred_vulnerability_score | Unknown | External website vulnerability score. | 

#### Command example

```!asm-list-external-website authentiaction=Form limit=5```

#### Context Example

```json
{
    "ASM":{
    "ExternalWebsite": {
        "total_count": 3343,
        "result_count": 5,
        "websites": [
            {
                "website_id": null,
                "host": "example.com",
                "protocol": "HTTPS",
                "is_active": "ACTIVE",
                "site_categories": [],
                "technology_ids": [
                    "http-2",
                    "google-font-api",
                    "hsts"
                ],
                "first_observed": 1704494700000,
                "last_observed": 1705363560000,
                "provider_names": [
                    "Google"
                ],
                "ips": [
                    "1.1.1.1"
                ],
                "port": 443,
                "active_service_ids": [
                    null
                ],
                "http_type": "HTTPS",
                "third_party_script_domains": [],
                "security_assessments": [
                    {
                        "name": "Has HTTPS Enabled",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "This website uses HTTPS which encrypts data in transit between browser and server."
                        }
                    },
                    {
                        "name": "Secure Forms",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "Forms on this website are submitted over HTTPS."
                        }
                    },
                    {
                        "name": "No Mixed Content",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "Pages on this website do not include content fetched using cleartext HTTP."
                        }
                    },
                    {
                        "name": "Protocol Downgrade",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "Redirects never downgrade from HTTPS to HTTP."
                        }
                    },
                    {
                        "name": "Sets valid X-Frame-Options Header",
                        "priority": 10,
                        "score": 0,
                        "securityAssessmentDetails": {
                            "pages": [
                                {
                                    "url": "https://example.com",
                                    "message": "not_set",
                                    "elements": []
                                }
                            ],
                            "description": "This header prevents browser from rendering this site inside an iframe or other embedding methods. This helps to prevent click-jacking attacks."
                        }
                    },
                    {
                        "name": "Sets valid X-Content-Type-Options Header",
                        "priority": 10,
                        "score": 0,
                        "securityAssessmentDetails": {
                            "pages": [
                                {
                                    "url": "https://example.com",
                                    "message": "not_set",
                                    "elements": []
                                }
                            ],
                            "description": "This header is used by the server to prevent browsers from guessing the media type (MIME type) known as MIME sniffing. The absence of this header might cause browsers to transform non-executable content into executable content."
                        }
                    },
                    {
                        "name": "Sets valid Content-Type Header",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "This header is used to indicate the original media type of the resource. The charset attribute is necessary in this header to prevent XSS in HTML pages."
                        }
                    },
                    {
                        "name": "Sets HTTP Strict Transport Security Header",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "This website sets a HSTS Header which ensures that the browser will always request the encrypted HTTPS version of the website regardless of what links are clicked or URL a site visitor enters."
                        }
                    },
                    {
                        "name": "Sets valid Referrer-Policy Header",
                        "priority": 10,
                        "score": 0,
                        "securityAssessmentDetails": {
                            "pages": [
                                {
                                    "url": "https://example.com",
                                    "message": "not_set",
                                    "elements": []
                                }
                            ],
                            "description": "This HTTP header controls how much referrer information should be included with requests. Today, the default behavior in modern browsers is to no longer send all referrer information (origin, path, and query string) to the same site but to only send the origin to other sites. However, since not all users may be using the latest browsers we suggest forcing this behavior by sending this header on all requests."
                        }
                    }
                ],
                "authentication": [
                    "Form Based Auth"
                ],
                "rootPageHttpStatusCode": "302",
                "isNonConfiguredHost": false,
                "externally_inferred_vulnerability_score": null,
                "externally_inferred_cves": [],
                "tags": [
                    "nemo"
                ]
            },
            {
                "website_id": null,
                "host": "example.com",
                "protocol": "HTTPS",
                "is_active": "ACTIVE",
                "site_categories": [],
                "technology_ids": [
                    "http-2",
                    "google-font-api",
                    "hsts"
                ],
                "first_observed": 1704494700000,
                "last_observed": 1705363560000,
                "provider_names": [
                    "Google"
                ],
                "ips": [
                    "1.1.1.1"
                ],
                "port": 443,
                "active_service_ids": [
                    null
                ],
                "http_type": "HTTPS",
                "third_party_script_domains": [],
                "security_assessments": [
                    {
                        "name": "Has HTTPS Enabled",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "This website uses HTTPS which encrypts data in transit between browser and server."
                        }
                    },
                    {
                        "name": "Secure Forms",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "Forms on this website are submitted over HTTPS."
                        }
                    },
                    {
                        "name": "No Mixed Content",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "Pages on this website do not include content fetched using cleartext HTTP."
                        }
                    },
                    {
                        "name": "Protocol Downgrade",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "Redirects never downgrade from HTTPS to HTTP."
                        }
                    },
                    {
                        "name": "Sets valid X-Frame-Options Header",
                        "priority": 10,
                        "score": 0,
                        "securityAssessmentDetails": {
                            "pages": [
                                {
                                    "url": "https://example.com",
                                    "message": "not_set",
                                    "elements": []
                                }
                            ],
                            "description": "This header prevents browser from rendering this site inside an iframe or other embedding methods. This helps to prevent click-jacking attacks."
                        }
                    },
                    {
                        "name": "Sets valid X-Content-Type-Options Header",
                        "priority": 10,
                        "score": 0,
                        "securityAssessmentDetails": {
                            "pages": [
                                {
                                    "url": "https://example.com",
                                    "message": "not_set",
                                    "elements": []
                                }
                            ],
                            "description": "This header is used by the server to prevent browsers from guessing the media type (MIME type) known as MIME sniffing. The absence of this header might cause browsers to transform non-executable content into executable content."
                        }
                    },
                    {
                        "name": "Sets valid Content-Type Header",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "This header is used to indicate the original media type of the resource. The charset attribute is necessary in this header to prevent XSS in HTML pages."
                        }
                    },
                    {
                        "name": "Sets HTTP Strict Transport Security Header",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "This website sets a HSTS Header which ensures that the browser will always request the encrypted HTTPS version of the website regardless of what links are clicked or URL a site visitor enters."
                        }
                    },
                    {
                        "name": "Sets valid Referrer-Policy Header",
                        "priority": 10,
                        "score": 0,
                        "securityAssessmentDetails": {
                            "pages": [
                                {
                                    "url": "https://example.com",
                                    "message": "not_set",
                                    "elements": []
                                }
                            ],
                            "description": "This HTTP header controls how much referrer information should be included with requests. Today, the default behavior in modern browsers is to no longer send all referrer information (origin, path, and query string) to the same site but to only send the origin to other sites. However, since not all users may be using the latest browsers we suggest forcing this behavior by sending this header on all requests."
                        }
                    }
                ],
                "authentication": [
                    "Form Based Auth"
                ],
                "rootPageHttpStatusCode": "302",
                "isNonConfiguredHost": false,
                "externally_inferred_vulnerability_score": null,
                "externally_inferred_cves": [],
                "tags": [
                    "nemo"
                ]
            },
            {
                "website_id": null,
                "host": "example.com",
                "protocol": "HTTPS",
                "is_active": "ACTIVE",
                "site_categories": [],
                "technology_ids": [
                    "http-2",
                    "google-font-api",
                    "hsts"
                ],
                "first_observed": 1704494700000,
                "last_observed": 1705363560000,
                "provider_names": [
                    "Google"
                ],
                "ips": [
                    "1.1.1.1"
                ],
                "port": 443,
                "active_service_ids": [
                    null
                ],
                "http_type": "HTTPS",
                "third_party_script_domains": [],
                "security_assessments": [
                    {
                        "name": "Has HTTPS Enabled",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "This website uses HTTPS which encrypts data in transit between browser and server."
                        }
                    },
                    {
                        "name": "Secure Forms",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "Forms on this website are submitted over HTTPS."
                        }
                    },
                    {
                        "name": "No Mixed Content",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "Pages on this website do not include content fetched using cleartext HTTP."
                        }
                    },
                    {
                        "name": "Protocol Downgrade",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "Redirects never downgrade from HTTPS to HTTP."
                        }
                    },
                    {
                        "name": "Sets valid X-Frame-Options Header",
                        "priority": 10,
                        "score": 0,
                        "securityAssessmentDetails": {
                            "pages": [
                                {
                                    "url": "https://example.com",
                                    "message": "not_set",
                                    "elements": []
                                }
                            ],
                            "description": "This header prevents browser from rendering this site inside an iframe or other embedding methods. This helps to prevent click-jacking attacks."
                        }
                    },
                    {
                        "name": "Sets valid X-Content-Type-Options Header",
                        "priority": 10,
                        "score": 0,
                        "securityAssessmentDetails": {
                            "pages": [
                                {
                                    "url": "https://example.com",
                                    "message": "not_set",
                                    "elements": []
                                }
                            ],
                            "description": "This header is used by the server to prevent browsers from guessing the media type (MIME type) known as MIME sniffing. The absence of this header might cause browsers to transform non-executable content into executable content."
                        }
                    },
                    {
                        "name": "Sets valid Content-Type Header",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "This header is used to indicate the original media type of the resource. The charset attribute is necessary in this header to prevent XSS in HTML pages."
                        }
                    },
                    {
                        "name": "Sets HTTP Strict Transport Security Header",
                        "priority": 10,
                        "score": 1,
                        "securityAssessmentDetails": {
                            "pages": [],
                            "description": "This website sets a HSTS Header which ensures that the browser will always request the encrypted HTTPS version of the website regardless of what links are clicked or URL a site visitor enters."
                        }
                    },
                    {
                        "name": "Sets valid Referrer-Policy Header",
                        "priority": 10,
                        "score": 0,
                        "securityAssessmentDetails": {
                            "pages": [
                                {
                                    "url": "https://example.com",
                                    "message": "not_set",
                                    "elements": []
                                }
                            ],
                            "description": "This HTTP header controls how much referrer information should be included with requests. Today, the default behavior in modern browsers is to no longer send all referrer information (origin, path, and query string) to the same site but to only send the origin to other sites. However, since not all users may be using the latest browsers we suggest forcing this behavior by sending this header on all requests."
                        }
                    }
                ],
                "authentication": [
                    "Form Based Auth"
                ],
                "rootPageHttpStatusCode": "302",
                "isNonConfiguredHost": false,
                "externally_inferred_vulnerability_score": null,
                "externally_inferred_cves": [],
                "tags": [
                    "nemo"
                ]
            }
            ]
        }
    }
}
```

#### Human Readable Output

>### External websites
>
>|Host|Authentication Type|
>|---|---|
>| example.com | Form based authentication | 


### asm-add-note-to-asset

#### Base Command

`asm-add-note-to-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Authentication type string on which to search. | Required | 
| entity_type | Maximum number of assets to return. The default and maximum is 100. | Required | 
| note_to_add | The custom note to be added to the notes section of the asset in Cortex Xpanse | Required |
| should_append | Set to 'false' to overwrite the current note on the asset. Set to 'true' to append to the current note. Default is 'true'. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.AssetAnnotation.status | String | Status of the note being added to the asset in Xpanse. | 

#### Command example


```!asm-add-note-to-asset asset_id=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx entity_type=asset note_to_add="Test adding note to asset."```


#### Context Example

```json
{
    "status": "succeeded"
}
```

#### Human Readable Output

> ### Status
> 
>|Status|
>|---|
>| succeeded |


### asm-reset-last-run

***
Resets the fetch incidents last run value, which resets the fetch to its initial fetch state.


#### Base Command

`asm-reset-last-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.