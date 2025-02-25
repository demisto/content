Integration to pull assets and other ASM related information.
This integration was integrated and tested with version 1.2.0 of Cortex Attack Surface Management.

## Configure Cortex Attack Surface Management


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The web UI with \`api-\` appended to front \(e.g., https://api-xsiam.paloaltonetworks.com\). For more information please see https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis. | True |
| API Key ID | For more information please see <https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis>.  Only a standard API key type is supported. | True |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


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
| ASM.ExternalService.externally_detected_providers | String | Providers of an external service. | 
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

>|Active Classifications|Business Units|Details|Discovery Type|Externally Detected Providers|Externally Inferred Cves|Externally Inferred Vulnerability Score|First Observed|Ip Address|Is Active|Last Observed|Port|Protocol|Service Id|Service Name|Service Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| SSHWeakMACAlgorithmsEnabled,<br/>SshServer,<br/>OpenSSH | Acme | serviceKey: 1.1.1.1:22<br/>serviceKeyType: IP<br/>businessUnits: {'name': 'Acme'}<br/>providerDetails: {'name': 'AWS', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}<br/>certificates: <br/>domains: <br/>ips: {'ip': 873887795, 'protocol': 'TCP', 'provider': 'AWS', 'geolocation': {'latitude': 39.0438, 'longitude': -77.4879, 'countryCode': 'US', 'city': 'ASHBURN', 'regionCode': 'VA', 'timeZone': None}, 'activityStatus': 'Active', 'lastObserved': 1663026500000, 'firstObserved': 1662774169000}<br/>classifications: {'name': 'SshServer', 'activityStatus': 'Active', 'values': [{'jsonValue': '{"version":"2.0","serverVersion":"OpenSSH_7.6p1","extraInfo":"Ubuntu-4ubuntu0.7"}', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}], 'firstObserved': 1662774120000, 'lastObserved': 1663026480000},<br/>{'name': 'SSHWeakMACAlgorithmsEnabled', 'activityStatus': 'Active', 'values': [{'jsonValue': '{}', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}], 'firstObserved': 1662774120000, 'lastObserved': 1663026480000},<br/>{'name': 'OpenSSH', 'activityStatus': 'Active', 'values': [{'jsonValue': '{"version":"7.6"}', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}], 'firstObserved': 1662774120000, 'lastObserved': 1663026480000}<br/>tlsVersions: <br/>inferredCvesObserved: {'inferredCve': {'cveId': 'CVE-2020-15778', 'cvssScoreV2': 6.8, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 7.8, 'cveSeverityV3': 'HIGH', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2021-41617', 'cvssScoreV2': 4.4, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 7.0, 'cveSeverityV3': 'HIGH', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6110', 'cvssScoreV2': 4.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 6.8, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6109', 'cvssScoreV2': 4.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 6.8, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2020-14145', 'cvssScoreV2': 4.3, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.9, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2019-6111', 'cvssScoreV2': 5.8, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.9, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2018-20685', 'cvssScoreV2': 2.6, 'cveSeverityV2': 'LOW', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2018-15919', 'cvssScoreV2': 5.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2016-20012', 'cvssScoreV2': 4.3, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2018-15473', 'cvssScoreV2': 5.0, 'cveSeverityV2': 'MEDIUM', 'cvssScoreV3': 5.3, 'cveSeverityV3': 'MEDIUM', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000},<br/>{'inferredCve': {'cveId': 'CVE-2021-36368', 'cvssScoreV2': 2.6, 'cveSeverityV2': 'LOW', 'cvssScoreV3': 3.7, 'cveSeverityV3': 'LOW', 'inferredCveMatchMetadata': {'inferredCveMatchType': 'ExactVersionMatch', 'product': 'openssh', 'confidence': 'High', 'vendor': 'openbsd', 'version': '7.6'}}, 'activityStatus': 'Active', 'firstObserved': 1662774169000, 'lastObserved': 1663026500000}<br/>enrichedObservationSource: CLOUD<br/>ip_ranges: {} | ColocatedOnIp | Amazon Web Services | CVE-2020-15778,<br/>CVE-2021-41617,<br/>CVE-2019-6110,<br/>CVE-2019-6109,<br/>CVE-2020-14145,<br/>CVE-2019-6111,<br/>CVE-2018-20685,<br/>CVE-2018-15919,<br/>CVE-2016-20012,<br/>CVE-2018-15473,<br/>CVE-2021-36368 | 7.8 | 1662774120000 | 1.1.1.1 | Active | 1663026480000 | 22 | TCP | 94232f8a-f001-3292-aa65-63fa9d981427 | SSH Server at 1.1.1.1:22 | SshServer |


### asm-list-external-ip-address-range

***
Get a list of all your internet exposure filtered by business units and organization handles. Maximum result limit is 100 ranges.

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

>|Active Responsive Ips Count|Business Units|Date Added|Details|First Ip|Ips Count|Last Ip|Organization Handles|Range Id|
>|---|---|---|---|---|---|---|---|
>| 0 | VanDelay Industries | 1663031000145 | 1.1.1.1 | 64 | 1.1.1.1 | MAINT-HK-PCCW-BIA-CS,<br/>BNA2-AP,<br/>TA66-AP | 4da29b7f-3086-3b52-981b-aa8ee5da1e60 |
>| 0 | VanDelay Industries | 1663031000144 | 1.1.1.1 | 16 | 1.1.1.1 | AR17615-RIPE,<br/>EASYNET-UK-MNT,<br/>JW372-RIPE,<br/>EH92-RIPE | 6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5 |


### asm-get-external-ip-address-range

***
Get the external IP address range details according to the range IDs.

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

>|Active Responsive Ips Count|Business Units|Date Added|First Ip|Ips Count|Last Ip|Organization Handles|Range Id|
>|---|---|---|---|---|---|---|---|---|
>| 0 | VanDelay Industries | 1663031000145 | networkRecords: {'handle': '1.1.1.1 - 1.1.1.1', 'firstIp': '1.1.1.1', 'lastIp': '1.1.1.1', 'name': 'SEARS-HK', 'whoIsServer': 'whois.apnic.net', 'lastChanged': 1663030241931, 'organizationRecords': [{'handle': 'MAINT-HK-PCCW-BIA-CS', 'dateAdded': 1663029346957, 'address': '', 'email': 'noc@acme.com', 'phone': '', 'org': '', 'formattedName': '', 'kind': 'group', 'roles': ['registrant'], 'lastChanged': None, 'firstRegistered': None, 'remarks': ''}, {'handle': 'BNA2-AP', 'dateAdded': 1663029346957, 'address': "27/F, PCCW Tower, Taikoo Place,\n979 King's Road, Quarry Bay, HK          ", 'email': 'cs@acme.com', 'phone': '+852-2888-6932', 'org': '', 'formattedName': 'BIZ NETVIGATOR ADMINISTRATORS', 'kind': 'group', 'roles': ['administrative'], 'lastChanged': 1514892767000, 'firstRegistered': 1220514857000, 'remarks': ''}, {'handle': 'TA66-AP', 'dateAdded': 1663029346957, 'address': 'HKT Limited\nPO Box 9896 GPO          ', 'email': 'noc@acme.com', 'phone': '+852-2883-5151', 'org': '', 'formattedName': 'TECHNICAL ADMINISTRATORS', 'kind': 'group', 'roles': ['technical'], 'lastChanged': 1468555410000, 'firstRegistered': 1220514856000, 'remarks': ''}], 'remarks': 'Sears Holdings Global Sourcing Ltd'} | 1.1.1.1 | 64 | 1.1.1.1 | MAINT-HK-PCCW-BIA-CS,<br/>BNA2-AP,<br/>TA66-AP | 4da29b7f-3086-3b52-981b-aa8ee5da1e60 |


### asm-list-asset-internet-exposure

***
Get a list of all your internet exposure filtered by IP address, domain, type, asm id, IPv6 address, AWS/GCP/Azure tags, has XDR agent, Externally detected providers, Externally inferred cves, Business units list, has BU overrides and/or if there is an active external service. Maximum result limit is 100 assets.

#### Base Command

`asm-list-asset-internet-exposure`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address on which to search. | Optional | 
| name | Name of the asset on which to search. | Optional | 
| type | Type of the external service. Possible values are: certificate, cloud_compute_instance, on_prem, domain, unassociated_responsive_ip. | Optional | 
| has_active_external_services | Whether the internet exposure has an active external service. Possible values are: yes, no. | Optional | 
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
| ASM.AssetInternetExposure.agent_id | Unknown | If there is an endpoint installed on this asset, this is the endpoint ID. | 
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
| ASM.AssetInternetExposure.certificate_classifications | String | Asset certificate.classifications. | 
| ASM.AssetInternetExposure.resolves | Boolean | Whether the asset has a DNS resolution. | 
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
                    "subject": "C=US,ST=New Jersey,L=Wayne,O=Acme,OU=MIS,CN=*.babiesrus.com",
                    "subjectAlternativeNames": "*.babiesrus.com",
                    "subjectCountry": "US",
                    "subjectEmail": null,
                    "subjectLocality": "Wayne",
                    "subjectName": "*.babiesrus.com",
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
            "name": "*.babiesrus.com",
            "resolves": false,
            "type": "Certificate"
        }
    }
}
```

#### Human Readable Output

>### Asset Internet Exposure

>|Asm Ids|Business Units|Certificate Algorithm|Certificate Classifications|Certificate Issuer|Created|Details|Name|Resolves|Type|
>|---|---|---|---|---|---|---|---|---|---|
>| 3c176460-8735-333c-b618-8262e2fb660c | Acme | SHA1withRSA | Wildcard,<br/>Expired,<br/>InsecureSignature | Thawte | 1663030146931 | providerDetails: <br/>domain: null<br/>topLevelAssetMapperDomain: null<br/>domainAssetType: null<br/>isPaidLevelDomain: false<br/>domainDetails: null<br/>dnsZone: null<br/>latestSampledIp: null<br/>subdomainMetadata: null<br/>recentIps: <br/>businessUnits: {'name': 'Acme'}<br/>certificateDetails: {"issuer": "C=US,O=Thawte\\, Inc.,CN=Thawte SSL CA", "issuerAlternativeNames": "", "issuerCountry": "US", "issuerEmail": null, "issuerLocality": null, "issuerName": "Thawte SSL CA", "issuerOrg": "Thawte\\\\, Inc.", "formattedIssuerOrg": "Thawte", "issuerOrgUnit": null, "issuerState": null, "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp21W/QVHuo0Nyy9l6Qp6Ye7yniuCccplWLdkL34pB0roNWBiklLJFftFTXJLtUuYEBhEbUtOPtNr5QRZFo+LQSj+JMQsGajEgNvIIMDms2xtc+vYkuJeNRsN/0zRm8iBjCNEZ0zBbWdupO6xee+Lngq5RiyRzAN2+Q5HlmHmVOcc7NtY5VIQhajp3a5Gc7tmLXa7ZxwQb+afdlpmE0iv4ZxmXFyHwlPXUlIxfETDDjtv2EzAgrnpZ5juo7TEFZA7AjsT0lO6cC2qPE9x9kC02PeC1Heg4hWf70CsXcKQBsprLqusrPYM9+OYfZnj+Dq9j6FjZD314Nz4qTGwmZrwDQIDAQAB", "publicKeyAlgorithm": "RSA", "publicKeyRsaExponent": 65537, "signatureAlgorithm": "SHA1withRSA", "subject": "C=US,ST=New Jersey,L=Wayne,O=Acme,OU=MIS,CN=*.babiesrus.com", "subjectAlternativeNames": "*.babiesrus.com", "subjectCountry": "US", "subjectEmail": null, "subjectLocality": "Wayne", "subjectName": "*.babiesrus.com", "subjectOrg": "Acme", "subjectOrgUnit": "MIS", "subjectState": "New Jersey", "serialNumber": "91384582774546160650506315451812470612", "validNotBefore": 1413158400000, "validNotAfter": 1444780799000, "version": "3", "publicKeyBits": 2048, "publicKeyModulus": "a76d56fd0547ba8d0dcb2f65e90a7a61eef29e2b8271ca6558b7642f7e29074ae83560629252c915fb454d724bb54b981018446d4b4e3ed36be50459168f8b4128fe24c42c19a8c480dbc820c0e6b36c6d73ebd892e25e351b0dff4cd19bc8818c2344674cc16d676ea4eeb179ef8b9e0ab9462c91cc0376f90e479661e654e71cecdb58e5521085a8e9ddae4673bb662d76bb671c106fe69f765a661348afe19c665c5c87c253d75252317c44c30e3b6fd84cc082b9e96798eea3b4c415903b023b13d253ba702daa3c4f71f640b4d8f782d477a0e2159fef40ac5dc29006ca6b2eabacacf60cf7e3987d99e3f83abd8fa163643df5e0dcf8a931b0999af00d", "publicKeySpki": "Up3fHwOddA9cXEeO4XBOgn63bfnvkXsOrOv6AycwQAk=", "sha1Fingerprint": "77d025c36f055e254063ae2ac3625fd4bf4507fb", "sha256Fingerprint": "9a37c952ee1169cfa6e91efb57fe6d405d1ca48b26a714e9a46f008c15ea62e8", "md5Fingerprint": "498ec19ebd6c6883ecd43d064e713002"}<br/>inferredCvesObserved: <br/>ip_ranges: {} | *.babiesrus.com | false | Certificate |


### asm-list-remediation-rule

***
Returns list of remediation path rules.

#### Base Command

`asm-list-remediation-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_rule_id | A string representing the ASM rule ID you want to get the associated remediation path rules for. | Required | 
| sort_by_creation_time | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). Possible values are: asc, desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.RemediationRule.rule_id | String | Remediation path rule UUID. | 
| ASM.RemediationRule.rule_name | String | Remediation path rule name. | 
| ASM.RemediationRule.description | String | Remediation path rule description. | 
| ASM.RemediationRule.attack_surface_rule_id | String | Association ASM rule ID for the remediation path rules. | 
| ASM.RemediationRule.criteria | Unknown | Array of remediation path rule criteria. | 
| ASM.RemediationRule.criteria_conjunction | String | Whether criteria is processed with AND or OR. | 
| ASM.RemediationRule.action | String | Action to take on rule match. | 
| ASM.RemediationRule.created_by | String | Email of who created the rule. | 
| ASM.RemediationRule.created_by_pretty | String | Readable name of who created the rule. | 
| ASM.RemediationRule.created_at | Date | Date the rule was created. | 

#### Command example

```!asm-list-remediation-rule asm_rule_id=RdpServer sort_by_creation_time=desc```

#### Context Example

```json
{
    "ASM": {
        "RemediationRule": {
            "action": "Email",
            "attack_surface_rule_id": "RdpServer",
            "created_at": 1672897301000,
            "created_by": "test@test.com",
            "created_by_pretty": "Test User",
            "criteria": [
                {
                    "field": "severity",
                    "operator": "eq",
                    "value": "high"
                },
                {
                    "field": "isCloudManaged",
                    "operator": "eq",
                    "value": "true"
                }
            ],
            "criteria_conjunction": "AND",
            "description": "for testing",
            "rule_id": "b935cf69-add9-4e75-8c3d-fe32ee471554",
            "rule_name": "TestRule"
        }
    }
}
```

#### Human Readable Output

>### Remediation Rules

>|Action|Attack Surface Rule Id|Created At|Created By|Created By Pretty|Criteria|Criteria Conjunction|Description|Rule Id|Rule Name|
>|---|---|---|---|---|---|---|---|---|---|
>| Email | RdpServer | 1672897301000 | test@test.com | Test User | {'field': 'severity', 'value': 'high', 'operator': 'eq'},<br/>{'field': 'isCloudManaged', 'value': 'true', 'operator': 'eq'} | AND | for testing | b935cf69-add9-4e75-8c3d-fe32ee471554 | TestRule |


### asm-start-remediation-confirmation-scan

***
Starts a new Remediation Confirmation Scan or gets an existing scan ID.

#### Base Command

`asm-start-remediation-confirmation-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | The ID of the service in Cortex Xpanse associated with the alert. | Required | 
| attack_surface_rule_id | The Cortex Xpanse attack surface rule associated with the alert. | Required | 
| alert_internal_id | The Cortex Xpanse alert ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.RemediationScan.scanId | string | The ID returned for the created or existing scan. | 
| ASM.RemediationScan.scan_creation_status | string | The creation status of the scan \(based on HTTP status\). | 

#### Command example

`!asm-start-remediation_confirmation_scan service_id="abc12345-abab-1212-1212-abc12345abcd" attack_surface_rule_id="InsecureOpenSSH" alert_internal_id="1"`

#### Context Example

```json
{
    "ASM": {
        "RemediationScan": {
            "scanId": "abcdef12-3456-789a-bcde-fgh012345678",
            "scan_creation_status": "created"
        }
    }
}
```

#### Human Readable Output

> ### Creation of Remediation Confirmation Scan

> |Scanid|Scan Creation Status|
> |---|---|
> | abcdef12-3456-789a-bcde-fgh012345678 | created |


### asm-get-remediation-confirmation-scan-status

***
Get the status of an existing Remediation Confirmation Scan.

#### Base Command

`asm-get-remediation-confirmation-scan-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The ID of an existing remediation confirmation scan. | Required | 
| interval_in_seconds | The interval, in seconds, to poll for scan results of an existing Remediation Confirmation Scan. Default is 600. | Optional | 
| timeout_in_seconds | The timeout, in seconds, for polling for scan results of an existing Remediation Confirmation Scan. Default is 11000. | Optional | 
| hide_polling_output | Whether to hide the polling result (automatically filled by polling). | Optional | 
| polling | Whether to poll until there is at least one result. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.RemediationScan.status | string | Status of the Remediation Confirmation Scan. | 
| ASM.RemediationScan.result | string | Result of the Remediation Confirmation Scan. | 

#### Command example

`!asm-get-remediation-confirmation-scan-status scan_id="abcdef12-3456-789a-bcde-fgh012345678"`

#### Context Example

```json
{
    "ASM": {
        "RemediationScan": {
            "status": "SUCCESS", // Required
            "result": "REMEDIATED" // Optional (If not SUCCESS)
        }
    }
}
```

#### Human Readable Output

> ### Status of Remediation Confirmation Scan

> |status|result|
> |---|---|
> | SUCCESS | REMEDIATED |

### asm-get-attack-surface-rule

***
Get information of an attack surface rule ID.

#### Base Command

`asm-get-attack-surface-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack_surface_rule_id |  A comma-separated list of attack surface rule IDs. For example: RdpServer,InsecureOpenSSH. | Optional | 
| enabled_status | Get the info about rule IDs with enabled status on or off. Has to be comma separated. For example: on,off. | Optional | 
| priority | Get the info about rule IDs with a priority. Has to be comma separated. For example: high,medium. | Optional | 
| category | Get the info about rule IDs of a category. Has to be comma separated. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.AttackSurfaceRule.attack_surface_rule_id | unknown | Attack surface rule ID. | 
| ASM.AttackSurfaceRule.attack_surface_rule_name | unknown | Attack surface rule name. | 
| ASM.AttackSurfaceRule.category | unknown | Attack surface rule category. | 
| ASM.AttackSurfaceRule.enabled_status | unknown | Attack surface rule status. | 
| ASM.AttackSurfaceRule.priority | unknown | Attack surface rule priority. | 
| ASM.AttackSurfaceRule.remediation_guidance | unknown | Remediation guidance of attack surface rule. | 

#### Command example

`!asm-get-attack-surface-rule attack_surface_rule_id=RdpServer raw-response=true`

#### Context Example

```json
{
    "reply": {
        "attack_surface_rules": [
            {
                "attack_surface_rule_id": "RdpServer",
                "attack_surface_rule_name": "RDP Server",
                "category": "Attack Surface Reduction",
                "created": 1698113023000,
                "description": "Remote Desktop Protocol (RDP) servers provide remote access to a computer over a network connection. Externally accessible RDP servers pose a significant security risk as they are frequent targets for attackers and can be vulnerable to a variety of documented exploits.",
                "enabled_status": "ON",
                "knowledge_base_link": null,
                "modified": 1605140275000,
                "modified_by": null,
                "priority": "High",
                "remediation_guidance": "Recommendations to reduce the likelihood of malicious RDP attempts are as follows:\n\n1. Best practice is to not have RDP publicly accessible on the Internet and instead only on trusted local networks.\n2. Implement a risk-based approach that prioritizes patching RDP vulnerabilities that have known weaponized public exploits.\n3. Limit RDP access to a specific user group and implementing lockout policies is an additional measure to protect against RDP brute-forcing which is another common tactic used by attackers. In addition, enable NLA (Network Level Authentication) which is non-default on older versions.\n4. If remote access to RDP or terminal services is a business requirement, it should only be made accessible through a secure Virtual Private Network (VPN) connection with multi-factor authentication (MFA) to the corporate network or through a zero-trust remote access gateway."
            }
        ],
        "result_count": 1,
        "total_count": 1
    }
}
```

#### Human Readable Output

> ### Results

> |ATTACK_SURFACE_RULE_ID|ATTACK_SURFACE_RULE_NAME|CATEGORY|CREATED|DESCRIPTION|ENABLED_STATUS|KNOWLEDGE_BASE_LINK|MODIFIED|MODIFIED_BY|PRIORITY|REMEDIATION_GUIDANCE|
> |---|---|---|---|---|---|---|---|---|---|---|
> | RdpServer | RDP Server | Attack Surface Reduction | 1698113023000 | Remote Desktop Protocol (RDP) servers provide remote access to a computer over a network connection. Externally accessible RDP servers pose a significant security risk as they are frequent targets for attackers and can be vulnerable to a variety of documented exploits. | ON | | 1605140275000 | | High | Recommendations to reduce the likelihood of malicious RDP attempts are as follows:\n\n1. Best practice is to not have RDP publicly accessible on the Internet and instead only on trusted local networks.\n2. Implement a risk-based approach that prioritizes patching RDP vulnerabilities that have known weaponized public exploits.\n3. Limit RDP access to a specific user group and implementing lockout policies is an additional measure to protect against RDP brute-forcing which is another common tactic used by attackers. In addition, enable NLA (Network Level Authentication) which is non-default on older versions.\n4. If remote access to RDP or terminal services is a business requirement, it should only be made accessible through a secure Virtual Private Network (VPN) connection with multi-factor authentication (MFA) to the corporate network or through a zero-trust remote access gateway |