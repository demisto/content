# adding so null don't get seen as variable.
null = None
false = False

EXTERNAL_SERVICES_RESPONSE = {
    "reply": {
        "total_count": 5999,
        "result_count": 2,
        "external_services": [
            {
                "service_id": "8b8f9d0a-4acd-3d88-9042-c7d17c2b44e9",
                "service_name": "DNS Server at 1.1.1.1:53",
                "service_type": "DnsServer",
                "ip_address": [
                    "1.1.1.1"
                ],
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "is_active": "Inactive",
                "first_observed": 1661308020000,
                "last_observed": 1661357820000,
                "port": 53,
                "protocol": "UDP",
                "active_classifications": [],
                "inactive_classifications": [
                    "DnsServer"
                ],
                "discovery_type": "ColocatedOnIp",
                "business_units": [
                    "Acme"
                ],
                "externally_inferred_vulnerability_score": null,
                "externally_inferred_cves": []
            },
            {
                "service_id": "7a4ce6ec-9ce3-3002-ac66-862854b2d7f7",
                "service_name": "DNS Server at 1.1.1.1:53",
                "service_type": "DnsServer",
                "ip_address": [
                    "1.1.1.1"
                ],
                "domain": [],
                "externally_detected_providers": [
                    "Other"
                ],
                "is_active": "Active",
                "first_observed": 1661298300000,
                "last_observed": 1662536820000,
                "port": 53,
                "protocol": "UDP",
                "active_classifications": [
                    "DnsServer",
                    "ISCBIND9"
                ],
                "inactive_classifications": [],
                "discovery_type": "ColocatedOnIp",
                "business_units": [
                    "VanDelay Industries"
                ],
                "externally_inferred_vulnerability_score": 9.8,
                "externally_inferred_cves": [
                    "CVE-2021-25216",
                    "CVE-2020-8616",
                    "CVE-2020-8625",
                    "CVE-2017-3141",
                    "CVE-2015-5477",
                    "CVE-2015-5722",
                    "CVE-2016-9444",
                    "CVE-2017-3137",
                    "CVE-2016-8864",
                    "CVE-2016-9147",
                    "CVE-2016-9131",
                    "CVE-2018-5740",
                    "CVE-2016-2776",
                    "CVE-2021-25215",
                    "CVE-2017-3145",
                    "CVE-2018-5743",
                    "CVE-2015-5986",
                    "CVE-2016-6170",
                    "CVE-2021-25214",
                    "CVE-2020-8622",
                    "CVE-2018-5741",
                    "CVE-2017-3135",
                    "CVE-2016-9778",
                    "CVE-2016-2775",
                    "CVE-2017-3136",
                    "CVE-2020-8617",
                    "CVE-2017-3143",
                    "CVE-2017-3138",
                    "CVE-2021-25219",
                    "CVE-2019-6465",
                    "CVE-2018-5745",
                    "CVE-2017-3142"
                ]
            }
        ]
    }
}

EXTERNAL_SERVICE_RESPONSE = {
    "reply": {
        "details": [
            {
                "service_id": "94232f8a-f001-3292-aa65-63fa9d981427",
                "service_name": "SSH Server at 1.1.1.1:22",
                "service_type": "SshServer",
                "ip_address": [
                    "1.1.1.1"
                ],
                "domain": [],
                "externally_detected_providers": [
                    "Amazon Web Services"
                ],
                "is_active": "Active",
                "first_observed": 1662774120000,
                "last_observed": 1662967560000,
                "port": 22,
                "protocol": "TCP",
                "active_classifications": [
                    "SSHWeakMACAlgorithmsEnabled",
                    "SshServer",
                    "OpenSSH"
                ],
                "inactive_classifications": [],
                "discovery_type": "ColocatedOnIp",
                "business_units": [
                    "Acme"
                ],
                "externally_inferred_vulnerability_score": 7.8,
                "externally_inferred_cves": [
                    "CVE-2020-15778",
                    "CVE-2021-41617",
                    "CVE-2019-6110",
                    "CVE-2019-6109",
                    "CVE-2020-14145",
                    "CVE-2019-6111",
                    "CVE-2016-20012",
                    "CVE-2018-15473",
                    "CVE-2018-15919",
                    "CVE-2018-20685",
                    "CVE-2021-36368"
                ],
                "details": {
                    "serviceKey": "1.1.1.1:22",
                    "serviceKeyType": "IP",
                    "businessUnits": [
                        {
                            "name": "Acme"
                        }
                    ],
                    "providerDetails": [
                        {
                            "name": "AWS",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        }
                    ],
                    "certificates": [],
                    "domains": [],
                    "ips": [
                        {
                            "ip": 873887795,
                            "protocol": "TCP",
                            "provider": "AWS",
                            "geolocation": {
                                "latitude": 39.0438,
                                "longitude": -77.4879,
                                "countryCode": "US",
                                "city": "ASHBURN",
                                "regionCode": "VA",
                                "timeZone": null
                            },
                            "activityStatus": "Active",
                            "lastObserved": 1662967589000,
                            "firstObserved": 1662774169000
                        }
                    ],
                    "classifications": [
                        {
                            "name": "SshServer",
                            "activityStatus": "Active",
                            "values": [
                                {
                                    "jsonValue": "{\"version\":\"2.0\",\"serverVersion\":\"OpenSSH_7.6p1\",\"extraInfo\":\"Ubuntu-4ubuntu0.7\"}",
                                    "firstObserved": 1662774169000,
                                    "lastObserved": 1662967589000
                                }
                            ],
                            "firstObserved": 1662774120000,
                            "lastObserved": 1662967560000
                        },
                        {
                            "name": "SSHWeakMACAlgorithmsEnabled",
                            "activityStatus": "Active",
                            "values": [
                                {
                                    "jsonValue": "{}",
                                    "firstObserved": 1662774169000,
                                    "lastObserved": 1662958350000
                                }
                            ],
                            "firstObserved": 1662774120000,
                            "lastObserved": 1662958320000
                        },
                        {
                            "name": "OpenSSH",
                            "activityStatus": "Active",
                            "values": [
                                {
                                    "jsonValue": "{\"version\":\"7.6\"}",
                                    "firstObserved": 1662774169000,
                                    "lastObserved": 1662967589000
                                }
                            ],
                            "firstObserved": 1662774120000,
                            "lastObserved": 1662967560000
                        }
                    ],
                    "tlsVersions": [],
                    "inferredCvesObserved": [
                        {
                            "inferredCve": {
                                "cveId": "CVE-2020-15778",
                                "cvssScoreV2": 6.8,
                                "cveSeverityV2": "MEDIUM",
                                "cvssScoreV3": 7.8,
                                "cveSeverityV3": "HIGH",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2021-41617",
                                "cvssScoreV2": 4.4,
                                "cveSeverityV2": "MEDIUM",
                                "cvssScoreV3": 7.0,
                                "cveSeverityV3": "HIGH",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2019-6110",
                                "cvssScoreV2": 4.0,
                                "cveSeverityV2": "MEDIUM",
                                "cvssScoreV3": 6.8,
                                "cveSeverityV3": "MEDIUM",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2019-6109",
                                "cvssScoreV2": 4.0,
                                "cveSeverityV2": "MEDIUM",
                                "cvssScoreV3": 6.8,
                                "cveSeverityV3": "MEDIUM",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2020-14145",
                                "cvssScoreV2": 4.3,
                                "cveSeverityV2": "MEDIUM",
                                "cvssScoreV3": 5.9,
                                "cveSeverityV3": "MEDIUM",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2019-6111",
                                "cvssScoreV2": 5.8,
                                "cveSeverityV2": "MEDIUM",
                                "cvssScoreV3": 5.9,
                                "cveSeverityV3": "MEDIUM",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2016-20012",
                                "cvssScoreV2": 4.3,
                                "cveSeverityV2": "MEDIUM",
                                "cvssScoreV3": 5.3,
                                "cveSeverityV3": "MEDIUM",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2018-15473",
                                "cvssScoreV2": 5.0,
                                "cveSeverityV2": "MEDIUM",
                                "cvssScoreV3": 5.3,
                                "cveSeverityV3": "MEDIUM",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2018-15919",
                                "cvssScoreV2": 5.0,
                                "cveSeverityV2": "MEDIUM",
                                "cvssScoreV3": 5.3,
                                "cveSeverityV3": "MEDIUM",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2018-20685",
                                "cvssScoreV2": 2.6,
                                "cveSeverityV2": "LOW",
                                "cvssScoreV3": 5.3,
                                "cveSeverityV3": "MEDIUM",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        },
                        {
                            "inferredCve": {
                                "cveId": "CVE-2021-36368",
                                "cvssScoreV2": 2.6,
                                "cveSeverityV2": "LOW",
                                "cvssScoreV3": 3.7,
                                "cveSeverityV3": "LOW",
                                "inferredCveMatchMetadata": {
                                    "inferredCveMatchType": "ExactVersionMatch",
                                    "product": "openssh",
                                    "confidence": "High",
                                    "vendor": "openbsd",
                                    "version": "7.6"
                                }
                            },
                            "activityStatus": "Active",
                            "firstObserved": 1662774169000,
                            "lastObserved": 1662967589000
                        }
                    ],
                    "enrichedObservationSource": "CLOUD",
                    "ip_ranges": {}
                }
            }
        ]
    }
}

EXTERNAL_RANGES_RESPONSE = {
    "reply": {
        "total_count": 443,
        "result_count": 2,
        "external_ip_address_ranges": [
            {
                "range_id": "4da29b7f-3086-3b52-981b-aa8ee5da1e60",
                "first_ip": "1.1.1.1",
                "last_ip": "1.1.1.1",
                "ips_count": 64,
                "active_responsive_ips_count": 0,
                "date_added": 1662988031334,
                "business_units": [
                    "VanDelay Industries"
                ],
                "organization_handles": [
                    "MAINT-HK-PCCW-BIA-CS",
                    "TA66-AP",
                    "BNA2-AP"
                ]
            },
            {
                "range_id": "6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5",
                "first_ip": "1.1.1.1",
                "last_ip": "1.1.1.1",
                "ips_count": 16,
                "active_responsive_ips_count": 0,
                "date_added": 1662988031334,
                "business_units": [
                    "VanDelay Industries"
                ],
                "organization_handles": [
                    "EH92-RIPE",
                    "EASYNET-UK-MNT",
                    "AR17615-RIPE",
                    "JW372-RIPE"
                ]
            }
        ]
    }
}

EXTERNAL_RANGE_RESPONSE = {
    "reply": {
        "details": [
            {
                "range_id": "4da29b7f-3086-3b52-981b-aa8ee5da1e60",
                "first_ip": "1.1.1.1",
                "last_ip": "1.1.1.1",
                "ips_count": 64,
                "active_responsive_ips_count": 0,
                "date_added": 1662988031334,
                "business_units": [
                    "VanDelay Industries"
                ],
                "organization_handles": [
                    "MAINT-HK-PCCW-BIA-CS",
                    "TA66-AP",
                    "BNA2-AP"
                ],
                "details": {
                    "networkRecords": [
                        {
                            "handle": "1.1.1.1 - 1.1.1.1",
                            "firstIp": "1.1.1.1",
                            "lastIp": "1.1.1.1",
                            "name": "SEARS-HK",
                            "whoIsServer": "whois.apnic.net",
                            "lastChanged": 1662987151163,
                            "organizationRecords": [
                                {
                                    "handle": "MAINT-HK-PCCW-BIA-CS",
                                    "dateAdded": 1662986267926,
                                    "address": "",
                                    "email": "noc@acme.com",
                                    "phone": "",
                                    "org": "",
                                    "formattedName": "",
                                    "kind": "group",
                                    "roles": [
                                        "registrant"
                                    ],
                                    "lastChanged": null,
                                    "firstRegistered": null,
                                    "remarks": ""
                                },
                                {
                                    "handle": "TA66-AP",
                                    "dateAdded": 1662986267926,
                                    "address": "HKT Limited\nPO Box 9896 GPO          ",
                                    "email": "noc@acme.com",
                                    "phone": "+852-2883-5151",
                                    "org": "",
                                    "formattedName": "TECHNICAL ADMINISTRATORS",
                                    "kind": "group",
                                    "roles": [
                                        "technical"
                                    ],
                                    "lastChanged": 1468555410000,
                                    "firstRegistered": 1220514856000,
                                    "remarks": ""
                                },
                                {
                                    "handle": "BNA2-AP",
                                    "dateAdded": 1662986267926,
                                    "address": "27/F, PCCW Tower, Taikoo Place,\n979 King's Road, Quarry Bay, HK          ",
                                    "email": "cs@acme.com",
                                    "phone": "+852-2888-6932",
                                    "org": "",
                                    "formattedName": "BIZ NETVIGATOR ADMINISTRATORS",
                                    "kind": "group",
                                    "roles": [
                                        "administrative"
                                    ],
                                    "lastChanged": 1514892767000,
                                    "firstRegistered": 1220514857000,
                                    "remarks": ""
                                }
                            ],
                            "remarks": "Sears Holdings Global Sourcing Ltd"
                        }
                    ]
                }
            }
        ]
    }
}

EXTERNAL_EXPOSURES_RESPONSE = {
    "reply": {
        "total_count": 1591,
        "result_count": 2,
        "assets_internet_exposure": [
            {
                "asm_ids": [
                    "3c176460-8735-333c-b618-8262e2fb660c"
                ],
                "name": "*.acme.com",
                "asset_type": "CERTIFICATE",
                "cloud_provider": null,
                "externally_detected_providers": [],
                "region": null,
                "ips": [],
                "business_units": [
                    "Acme"
                ],
                "management_status": [],
                "iot_model": null,
                "iot_category": null,
                "iot_profile": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": [],
                "last_observed": null,
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired",
                    "InsecureSignature"
                ],
                "certificate_issuer": "Thawte",
                "certificate_algorithm": "SHA1withRSA",
                "mac_addresses": [],
                "cloud_id": null,
                "ip_ranges": [],
                "domain_resolves": false,
                "operation_system": null,
                "asm_va_score": null,
                "externally_inferred_cves": [],
                "agent_id": null
            },
            {
                "asm_ids": [
                    "43164fde-8e87-3d1e-8530-82f14cd3ae9a"
                ],
                "name": "*.ch3.intra.kmart.com",
                "asset_type": "CERTIFICATE",
                "cloud_provider": null,
                "externally_detected_providers": [],
                "region": null,
                "ips": [],
                "business_units": [
                    "VanDelay Industries"
                ],
                "management_status": [],
                "iot_model": null,
                "iot_category": null,
                "iot_profile": null,
                "sensor": [
                    "XPANSE"
                ],
                "service_type": [],
                "last_observed": null,
                "first_observed": null,
                "has_active_externally_services": false,
                "has_xdr_agent": "NA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired"
                ],
                "certificate_issuer": "COMODO",
                "certificate_algorithm": "SHA256withRSA",
                "mac_addresses": [],
                "cloud_id": null,
                "ip_ranges": [],
                "domain_resolves": false,
                "operation_system": null,
                "asm_va_score": null,
                "externally_inferred_cves": [],
                "agent_id": null
            }
        ]
    }
}

EXTERNAL_EXPOSURE_RESPONSE = {
    "reply": {
        "details": [
            {
                "asm_ids": "3c176460-8735-333c-b618-8262e2fb660c",
                "name": "*.acme.com",
                "type": "Certificate",
                "last_observed": null,
                "first_observed": null,
                "externally_detected_providers": [],
                "created": 1662987013779,
                "ips": [],
                "business_units": [
                    "Acme"
                ],
                "active_service_ids": [],
                "all_service_ids": [],
                "active_external_services_types": [],
                "domain": null,
                "certificate_issuer": "Thawte",
                "certificate_algorithm": "SHA1withRSA",
                "certificate_classifications": [
                    "Wildcard",
                    "Expired",
                    "InsecureSignature"
                ],
                "resolves": false,
                "details": {
                    "providerDetails": [],
                    "domain": null,
                    "topLevelAssetMapperDomain": null,
                    "domainAssetType": null,
                    "isPaidLevelDomain": false,
                    "domainDetails": null,
                    "dnsZone": null,
                    "latestSampledIp": null,
                    "subdomainMetadata": null,
                    "recentIps": [],
                    "businessUnits": [
                        {
                            "name": "Acme"
                        }
                    ],
                    "certificateDetails": {
                        "issuer": "C=US,O=Thawte\\, Inc.,CN=Thawte SSL CA",
                        "issuerAlternativeNames": "",
                        "issuerCountry": "US",
                        "issuerEmail": null,
                        "issuerLocality": null,
                        "issuerName": "Thawte SSL CA",
                        "issuerOrg": "Thawte\\\\, Inc.",
                        "formattedIssuerOrg": "Thawte",
                        "issuerOrgUnit": null,
                        "issuerState": null,
                        "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp21W/QVHuo0Nyy9l6Qp6Ye7yniuCccplWLdkL34pB0roNWBiklLJFftFTXJLtUuYEBhEbUtOPtNr5QRZFo+LQSj+JMQsGajEgNvIIMDms2xtc+vYkuJeNRsN/0zRm8iBjCNEZ0zBbWdupO6xee+Lngq5RiyRzAN2+Q5HlmHmVOcc7NtY5VIQhajp3a5Gc7tmLXa7ZxwQb+afdlpmE0iv4ZxmXFyHwlPXUlIxfETDDjtv2EzAgrnpZ5juo7TEFZA7AjsT0lO6cC2qPE9x9kC02PeC1Heg4hWf70CsXcKQBsprLqusrPYM9+OYfZnj+Dq9j6FjZD314Nz4qTGwmZrwDQIDAQAB",
                        "publicKeyAlgorithm": "RSA",
                        "publicKeyRsaExponent": 65537,
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
                        "serialNumber": "91384582774546160650506315451812470612",
                        "validNotBefore": 1413158400000,
                        "validNotAfter": 1444780799000,
                        "version": "3",
                        "publicKeyBits": 2048,
                        "publicKeyModulus": "a76d56fd0547ba8d0dcb2f65e90a7a61eef29e2b8271ca6558b7642f7e29074ae83560629252c915fb454d724bb54b981018446d4b4e3ed36be50459168f8b4128fe24c42c19a8c480dbc820c0e6b36c6d73ebd892e25e351b0dff4cd19bc8818c2344674cc16d676ea4eeb179ef8b9e0ab9462c91cc0376f90e479661e654e71cecdb58e5521085a8e9ddae4673bb662d76bb671c106fe69f765a661348afe19c665c5c87c253d75252317c44c30e3b6fd84cc082b9e96798eea3b4c415903b023b13d253ba702daa3c4f71f640b4d8f782d477a0e2159fef40ac5dc29006ca6b2eabacacf60cf7e3987d99e3f83abd8fa163643df5e0dcf8a931b0999af00d",
                        "publicKeySpki": "Up3fHwOddA9cXEeO4XBOgn63bfnvkXsOrOv6AycwQAk=",
                        "sha1Fingerprint": "77d025c36f055e254063ae2ac3625fd4bf4507fb",
                        "sha256Fingerprint": "9a37c952ee1169cfa6e91efb57fe6d405d1ca48b26a714e9a46f008c15ea62e8",
                        "md5Fingerprint": "498ec19ebd6c6883ecd43d064e713002"
                    },
                    "inferredCvesObserved": [],
                    "ip_ranges": {}
                },
                "external_services": [],
                "externally_inferred_vulnerability_score": null,
                "externally_inferred_cves": []
            }
        ]
    }
}

INTERNET_EXPOSURE_PRE_FORMAT = [
    {
        "asm_ids": [
            "3c176460-8735-333c-b618-8262e2fb660c"
        ],
        "name": "*.acme.com",
        "asset_type": "CERTIFICATE",
        "cloud_provider": null,
        "externally_detected_providers": [],
        "region": null,
        "ips": [],
        "business_units": [
            "Acme"
        ],
        "management_status": [],
        "iot_model": null,
        "iot_category": null,
        "iot_profile": null,
        "sensor": [
            "XPANSE"
        ],
        "service_type": [],
        "last_observed": null,
        "first_observed": null,
        "has_active_externally_services": false,
        "has_xdr_agent": "NA",
        "certificate_classifications": [
            "Wildcard",
            "Expired",
            "InsecureSignature"
        ],
        "certificate_issuer": "Thawte",
        "certificate_algorithm": "SHA1withRSA",
        "mac_addresses": [],
        "cloud_id": null,
        "ip_ranges": [],
        "domain_resolves": false,
        "operation_system": null,
        "asm_va_score": null,
        "externally_inferred_cves": [],
        "agent_id": null
    },
    {
        "asm_ids": [
            "43164fde-8e87-3d1e-8530-82f14cd3ae9a"
        ],
        "name": "*.ch3.intra.kmart.com",
        "asset_type": "CERTIFICATE",
        "cloud_provider": null,
        "externally_detected_providers": [],
        "region": null,
        "ips": [],
        "business_units": [
            "VanDelay Industries"
        ],
        "management_status": [],
        "iot_model": null,
        "iot_category": null,
        "iot_profile": null,
        "sensor": [
            "XPANSE"
        ],
        "service_type": [],
        "last_observed": null,
        "first_observed": null,
        "has_active_externally_services": false,
        "has_xdr_agent": "NA",
        "certificate_classifications": [
            "Wildcard",
            "Expired"
        ],
        "certificate_issuer": "COMODO",
        "certificate_algorithm": "SHA256withRSA",
        "mac_addresses": [],
        "cloud_id": null,
        "ip_ranges": [],
        "domain_resolves": false,
        "operation_system": null,
        "asm_va_score": null,
        "externally_inferred_cves": [],
        "agent_id": null
    }
]

LIST_ALERTS_RESPONSE = {
    "reply": {
        "total_count": 696,
        "result_count": 2,
        "alerts": [
            {
                "external_id": "FAKE-GUID",
                "severity": "high",
                "matching_status": "MATCHED",
                "end_match_attempt_ts": null,
                "local_insert_ts": 1659455267908,
                "last_modified_ts": 1660240725450,
                "bioc_indicator": null,
                "matching_service_rule_id": null,
                "attempt_counter": null,
                "bioc_category_enum_key": null,
                "is_whitelisted": false,
                "starred": false,
                "deduplicate_tokens": null,
                "filter_rule_id": null,
                "mitre_technique_id_and_name": null,
                "mitre_tactic_id_and_name": null,
                "agent_version": null,
                "agent_ip_addresses_v6": null,
                "agent_device_domain": null,
                "agent_fqdn": null,
                "agent_os_type": "NO_HOST",
                "agent_os_sub_type": null,
                "agent_data_collection_status": null,
                "mac": null,
                "is_pcap": false,
                "alert_type": "Unclassified",
                "resolution_status": "STATUS_070_RESOLVED_OTHER",
                "resolution_comment": "ASM alert resolution",
                "dynamic_fields": null,
                "events": [
                    {
                        "agent_install_type": "NA",
                        "agent_host_boot_time": null,
                        "event_sub_type": null,
                        "module_id": null,
                        "association_strength": null,
                        "dst_association_strength": null,
                        "story_id": null,
                        "event_id": null,
                        "event_type": null,
                        "event_timestamp": 1659452808759,
                        "actor_process_instance_id": null,
                        "actor_process_image_path": null,
                        "actor_process_image_name": null,
                        "actor_process_command_line": null,
                        "actor_process_signature_status": "N/A",
                        "actor_process_signature_vendor": null,
                        "actor_process_image_sha256": null,
                        "actor_process_image_md5": null,
                        "actor_process_causality_id": null,
                        "actor_causality_id": null,
                        "actor_process_os_pid": null,
                        "actor_thread_thread_id": null,
                        "causality_actor_process_image_name": null,
                        "causality_actor_process_command_line": null,
                        "causality_actor_process_image_path": null,
                        "causality_actor_process_signature_vendor": null,
                        "causality_actor_process_signature_status": "N/A",
                        "causality_actor_causality_id": null,
                        "causality_actor_process_execution_time": null,
                        "causality_actor_process_image_md5": null,
                        "causality_actor_process_image_sha256": null,
                        "action_file_path": null,
                        "action_file_name": null,
                        "action_file_md5": null,
                        "action_file_sha256": null,
                        "action_file_macro_sha256": null,
                        "action_registry_data": null,
                        "action_registry_key_name": null,
                        "action_registry_value_name": null,
                        "action_registry_full_key": null,
                        "action_local_ip": null,
                        "action_local_ip_v6": null,
                        "action_local_port": null,
                        "action_remote_ip": null,
                        "action_remote_ip_v6": null,
                        "action_remote_port": 80,
                        "action_external_hostname": null,
                        "action_country": "UNKNOWN",
                        "action_process_instance_id": null,
                        "action_process_causality_id": null,
                        "action_process_image_name": null,
                        "action_process_image_sha256": null,
                        "action_process_image_command_line": null,
                        "action_process_signature_status": "N/A",
                        "action_process_signature_vendor": null,
                        "os_actor_effective_username": null,
                        "os_actor_process_instance_id": null,
                        "os_actor_process_image_path": null,
                        "os_actor_process_image_name": null,
                        "os_actor_process_command_line": null,
                        "os_actor_process_signature_status": "N/A",
                        "os_actor_process_signature_vendor": null,
                        "os_actor_process_image_sha256": null,
                        "os_actor_process_causality_id": null,
                        "os_actor_causality_id": null,
                        "os_actor_process_os_pid": null,
                        "os_actor_thread_thread_id": null,
                        "fw_app_id": null,
                        "fw_interface_from": null,
                        "fw_interface_to": null,
                        "fw_rule": null,
                        "fw_rule_id": null,
                        "fw_device_name": null,
                        "fw_serial_number": null,
                        "fw_url_domain": null,
                        "fw_email_subject": null,
                        "fw_email_sender": null,
                        "fw_email_recipient": null,
                        "fw_app_subcategory": null,
                        "fw_app_category": null,
                        "fw_app_technology": null,
                        "fw_vsys": null,
                        "fw_xff": null,
                        "fw_misc": null,
                        "fw_is_phishing": "N/A",
                        "dst_agent_id": null,
                        "dst_causality_actor_process_execution_time": null,
                        "dns_query_name": null,
                        "dst_action_external_hostname": null,
                        "dst_action_country": null,
                        "dst_action_external_port": null,
                        "contains_featured_host": "NO",
                        "contains_featured_user": "NO",
                        "contains_featured_ip": "NO",
                        "image_name": null,
                        "container_id": null,
                        "cluster_name": null,
                        "referenced_resource": null,
                        "operation_name": null,
                        "identity_sub_type": null,
                        "identity_type": null,
                        "project": null,
                        "cloud_provider": null,
                        "resource_type": null,
                        "resource_sub_type": null,
                        "user_agent": null,
                        "user_name": null
                    }
                ],
                "alert_id": "231",
                "detection_timestamp": 1659452808759,
                "name": "Networking Infrastructure",
                "category": null,
                "endpoint_id": null,
                "description": "Networking and security infrastructure, such as firewalls and routers, generally should not have their administration panels open to public Internet. Compromise of these devices, often though password guessing or vulnerability exploitation, provides privileged access to an enterprise network.",
                "host_ip": null,
                "host_name": null,
                "mac_addresses": null,
                "source": "ASM",
                "action": "NOT_AVAILABLE",
                "action_pretty": "N/A",
                "tags": null
            },
            {
                "external_id": "FAKE-GUID",
                "severity": "high",
                "matching_status": "MATCHED",
                "end_match_attempt_ts": null,
                "local_insert_ts": 1659455246812,
                "last_modified_ts": 1660240426055,
                "bioc_indicator": null,
                "matching_service_rule_id": null,
                "attempt_counter": null,
                "bioc_category_enum_key": null,
                "is_whitelisted": false,
                "starred": false,
                "deduplicate_tokens": null,
                "filter_rule_id": null,
                "mitre_technique_id_and_name": null,
                "mitre_tactic_id_and_name": null,
                "agent_version": null,
                "agent_ip_addresses_v6": null,
                "agent_device_domain": null,
                "agent_fqdn": null,
                "agent_os_type": "NO_HOST",
                "agent_os_sub_type": null,
                "agent_data_collection_status": null,
                "mac": null,
                "is_pcap": false,
                "alert_type": "Unclassified",
                "resolution_status": "STATUS_070_RESOLVED_OTHER",
                "resolution_comment": "ASM alert resolution",
                "dynamic_fields": null,
                "events": [
                    {
                        "agent_install_type": "NA",
                        "agent_host_boot_time": null,
                        "event_sub_type": null,
                        "module_id": null,
                        "association_strength": null,
                        "dst_association_strength": null,
                        "story_id": null,
                        "event_id": null,
                        "event_type": null,
                        "event_timestamp": 1659452809020,
                        "actor_process_instance_id": null,
                        "actor_process_image_path": null,
                        "actor_process_image_name": null,
                        "actor_process_command_line": null,
                        "actor_process_signature_status": "N/A",
                        "actor_process_signature_vendor": null,
                        "actor_process_image_sha256": null,
                        "actor_process_image_md5": null,
                        "actor_process_causality_id": null,
                        "actor_causality_id": null,
                        "actor_process_os_pid": null,
                        "actor_thread_thread_id": null,
                        "causality_actor_process_image_name": null,
                        "causality_actor_process_command_line": null,
                        "causality_actor_process_image_path": null,
                        "causality_actor_process_signature_vendor": null,
                        "causality_actor_process_signature_status": "N/A",
                        "causality_actor_causality_id": null,
                        "causality_actor_process_execution_time": null,
                        "causality_actor_process_image_md5": null,
                        "causality_actor_process_image_sha256": null,
                        "action_file_path": null,
                        "action_file_name": null,
                        "action_file_md5": null,
                        "action_file_sha256": null,
                        "action_file_macro_sha256": null,
                        "action_registry_data": null,
                        "action_registry_key_name": null,
                        "action_registry_value_name": null,
                        "action_registry_full_key": null,
                        "action_local_ip": null,
                        "action_local_ip_v6": null,
                        "action_local_port": null,
                        "action_remote_ip": null,
                        "action_remote_ip_v6": null,
                        "action_remote_port": 80,
                        "action_external_hostname": null,
                        "action_country": "UNKNOWN",
                        "action_process_instance_id": null,
                        "action_process_causality_id": null,
                        "action_process_image_name": null,
                        "action_process_image_sha256": null,
                        "action_process_image_command_line": null,
                        "action_process_signature_status": "N/A",
                        "action_process_signature_vendor": null,
                        "os_actor_effective_username": null,
                        "os_actor_process_instance_id": null,
                        "os_actor_process_image_path": null,
                        "os_actor_process_image_name": null,
                        "os_actor_process_command_line": null,
                        "os_actor_process_signature_status": "N/A",
                        "os_actor_process_signature_vendor": null,
                        "os_actor_process_image_sha256": null,
                        "os_actor_process_causality_id": null,
                        "os_actor_causality_id": null,
                        "os_actor_process_os_pid": null,
                        "os_actor_thread_thread_id": null,
                        "fw_app_id": null,
                        "fw_interface_from": null,
                        "fw_interface_to": null,
                        "fw_rule": null,
                        "fw_rule_id": null,
                        "fw_device_name": null,
                        "fw_serial_number": null,
                        "fw_url_domain": null,
                        "fw_email_subject": null,
                        "fw_email_sender": null,
                        "fw_email_recipient": null,
                        "fw_app_subcategory": null,
                        "fw_app_category": null,
                        "fw_app_technology": null,
                        "fw_vsys": null,
                        "fw_xff": null,
                        "fw_misc": null,
                        "fw_is_phishing": "N/A",
                        "dst_agent_id": null,
                        "dst_causality_actor_process_execution_time": null,
                        "dns_query_name": null,
                        "dst_action_external_hostname": null,
                        "dst_action_country": null,
                        "dst_action_external_port": null,
                        "contains_featured_host": "NO",
                        "contains_featured_user": "NO",
                        "contains_featured_ip": "NO",
                        "image_name": null,
                        "container_id": null,
                        "cluster_name": null,
                        "referenced_resource": null,
                        "operation_name": null,
                        "identity_sub_type": null,
                        "identity_type": null,
                        "project": null,
                        "cloud_provider": null,
                        "resource_type": null,
                        "resource_sub_type": null,
                        "user_agent": null,
                        "user_name": null
                    }
                ],
                "alert_id": "33",
                "detection_timestamp": 1659452809020,
                "name": "Networking Infrastructure",
                "category": null,
                "endpoint_id": null,
                "description": "Networking and security infrastructure, such as firewalls and routers, generally should not have their administration panels open to public Internet. Compromise of these devices, often though password guessing or vulnerability exploitation, provides privileged access to an enterprise network.",
                "host_ip": null,
                "host_name": null,
                "mac_addresses": null,
                "source": "ASM",
                "action": "NOT_AVAILABLE",
                "action_pretty": "N/A",
                "tags": null
            }
        ]
    }
}

ATTACK_SURFACE_RULES_RAW = {
    "reply": {
        "total_count": 149,
        "result_count": 2,
        "attack_surface_rules": [
            {
                "attack_surface_rule_id": "SchneiderElectricEcoStruxureITGateway",
                "attack_surface_rule_name": "Schneider Electric EcoStruxure IT Gateway",
                "category": "Attack Surface Reduction",
                "created": 1689003841000,
                "description": "Schneider Electric EcoStruxure IT Gateway is a network management and monitoring solution used by organizations to monitor and manage their critical IT infrastruture on-premise, in the cloud, and at the edge. EcoStruxure provides visibility and information about resources across an organization regardless of vendor. This issue specifically identifies the EcoStruxure IT Gateway, the web management login portal EcoStruxure. The EcoStruxure IT Gateway is intended to be accessed from within a secure network and should not be exposed to the Internet. Version number of EcoStruxure is not identified through this policy.",
                "enabled_status": "On",
                "knowledge_base_link": null,
                "modified": 1688074708000,
                "modified_by": null,
                "priority": "High",
                "remediation_guidance": ""
            },
            {
                "attack_surface_rule_id": "Section889Violation",
                "attack_surface_rule_name": "Section 889 Violation",
                "category": "Attack Surface Reduction",
                "created": 1689003841000,
                "description": "Section 889 of the 2019 NDAA prohibits executive agencies from using equipment or services from five organizations: Huawei, Hikvision, Hytera, Dahua, and ZTE. This policy alerts you to usages of such equipment on your network. This policy does not have an Cortex Xpanse-defined default priority \u2013 customers enabling this rule can choose any default priority.\nNote: Other brands that utilize Dahua hardware / firmware may also be identified through this policy.",
                "enabled_status": "On",
                "knowledge_base_link": null,
                "modified": 1688074708000,
                "modified_by": null,
                "priority": "High",
                "remediation_guidance": "Investigate the devices that have been flagged under this policy and work with the owner of the affected assets to remove them from your network.\nFor clarification, Section 889 of the 2019 NDAA prohibits executive agencies from using equipment or services that have been flagged under this policy. (Huawei, Hikvision, Hytera, Dahua, ZTE)"
            }
        ]
    }
}

TAG_APPLY_RAW = {
    "reply": {
        "assign_tags": True
    }
}

TAG_REMOVE_RAW = {
    "reply": {
        "remove_tags": True
    }
}

LIST_INCIDENTS_RAW = {
    "reply": {
        "incidents": [
            {
                "aggregated_score": 75,
                "alert_categories": null,
                "alert_count": 4,
                "alerts_grouping_status": "Enabled",
                "assigned_user_mail": null,
                "assigned_user_pretty_name": null,
                "creation_time": 1688705047063,
                "critical_severity_alert_count": 0,
                "description": "'Google WebFramework Angular at suppliers.expander.expanse.co:443' detected by ASM on 3 hosts ",
                "detection_time": null,
                "high_severity_alert_count": 0,
                "host_count": 3,
                "hosts": [
                    "1.1.1.1:null",
                ],
                "incident_id": "5471",
                "incident_name": null,
                "incident_sources": [
                    "ASM"
                ],
                "low_severity_alert_count": 4,
                "manual_description": null,
                "manual_score": null,
                "manual_severity": null,
                "med_severity_alert_count": 0,
                "modification_time": 1689048065832,
                "notes": null,
                "original_tags": [
                    "BU:Prod Ev2 Branch"
                ],
                "resolve_comment": "",
                "resolved_timestamp": null,
                "rule_based_score": 75,
                "severity": "low",
                "starred": false,
                "status": "new",
                "tags": [],
                "user_count": 0,
                "xdr_url": "https://exp-test.crtx.eu.paloaltonetworks.com/incident-view?caseId=5471",
                "xpanse_risk_score": 75
            }
        ]
    }
}

INCIDENT_UPDATE_RAW = {
    "reply": True
}

ALERT_UPDATE_RAW = {
    "reply": {
        "alerts_ids": [
            602,
        ]
    }
}
