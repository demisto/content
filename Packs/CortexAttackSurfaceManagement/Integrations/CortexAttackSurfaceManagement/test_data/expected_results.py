# adding so null don't get seen as variable.
null = None
false = False

EXTERNAL_SERVICES_RESULTS = [
    {
        "active_classifications": [],
        "business_units": [
            "Acme"
        ],
        "discovery_type": "ColocatedOnIp",
        "domain": [],
        "externally_detected_providers": [
            "Other"
        ],
        "externally_inferred_cves": [],
        "externally_inferred_vulnerability_score": null,
        "first_observed": 1661308020000,
        "inactive_classifications": [
            "DnsServer"
        ],
        "ip_address": [
            "1.1.1.1"
        ],
        "is_active": "Inactive",
        "last_observed": 1661357820000,
        "port": 53,
        "protocol": "UDP",
        "service_id": "8b8f9d0a-4acd-3d88-9042-c7d17c2b44e9",
        "service_name": "DNS Server at 1.1.1.1:53",
        "service_type": "DnsServer"
    },
    {
        "active_classifications": [
            "DnsServer",
            "ISCBIND9"
        ],
        "business_units": [
            "VanDelay Industries"
        ],
        "discovery_type": "ColocatedOnIp",
        "domain": [],
        "externally_detected_providers": [
            "Other"
        ],
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
        ],
        "externally_inferred_vulnerability_score": 9.8,
        "first_observed": 1661298300000,
        "inactive_classifications": [],
        "ip_address": [
            "1.1.1.1"
        ],
        "is_active": "Active",
        "last_observed": 1662536820000,
        "port": 53,
        "protocol": "UDP",
        "service_id": "7a4ce6ec-9ce3-3002-ac66-862854b2d7f7",
        "service_name": "DNS Server at 1.1.1.1:53",
        "service_type": "DnsServer"
    }
]

EXTERNAL_SERVICE_RESULTS = [
    {
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
                    "lastObserved": 1662967560000,
                    "name": "SshServer",
                    "values": [
                        {
                            "firstObserved": 1662774169000,
                            "jsonValue": "{\"version\":\"2.0\",\"serverVersion\":\"OpenSSH_7.6p1\",\"extraInfo\":\"Ubuntu-4ubuntu0.7\"}",
                            "lastObserved": 1662967589000
                        }
                    ]
                },
                {
                    "activityStatus": "Active",
                    "firstObserved": 1662774120000,
                    "lastObserved": 1662958320000,
                    "name": "SSHWeakMACAlgorithmsEnabled",
                    "values": [
                        {
                            "firstObserved": 1662774169000,
                            "jsonValue": "{}",
                            "lastObserved": 1662958350000
                        }
                    ]
                },
                {
                    "activityStatus": "Active",
                    "firstObserved": 1662774120000,
                    "lastObserved": 1662967560000,
                    "name": "OpenSSH",
                    "values": [
                        {
                            "firstObserved": 1662774169000,
                            "jsonValue": "{\"version\":\"7.6\"}",
                            "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000
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
                    "lastObserved": 1662967589000,
                    "protocol": "TCP",
                    "provider": "AWS"
                }
            ],
            "providerDetails": [
                {
                    "firstObserved": 1662774169000,
                    "lastObserved": 1662967589000,
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
        "ipv6s": [
            "2600:1900:4000:9664:0:7::"
        ],
        "aws_cloud_tags": [
            "Name:AD Lab"
        ],
        "gcp_cloud_tags": [
            "Name:gcp Lab"
        ],
        "azure_cloud_tags": [
            "Name:azure Lab"
        ],
        "mac_address": ["00:11:22:33:44:55"],
        "has_bu_overrides": False,
        "has_xdr_agent": "NO",
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
        "externally_inferred_vulnerability_score": 7.8,
        "first_observed": 1662774120000,
        "inactive_classifications": [],
        "ip_address": [
            "1.1.1.1"
        ],
        "is_active": "Active",
        "last_observed": 1662967560000,
        "port": 22,
        "protocol": "TCP",
        "service_id": "94232f8a-f001-3292-aa65-63fa9d981427",
        "service_name": "SSH Server at 1.1.1.1:22",
        "service_type": "SshServer"
    }
]

EXTERNAL_RANGES_RESULTS = [
    {
        "active_responsive_ips_count": 0,
        "business_units": [
            "VanDelay Industries"
        ],
        "date_added": 1662988031334,
        "first_ip": "1.1.1.1",
        "ips_count": 64,
        "last_ip": "1.1.1.1",
        "organization_handles": [
            "MAINT-HK-PCCW-BIA-CS",
            "TA66-AP",
            "BNA2-AP"
        ],
        "range_id": "4da29b7f-3086-3b52-981b-aa8ee5da1e60"
    },
    {
        "active_responsive_ips_count": 0,
        "business_units": [
            "VanDelay Industries"
        ],
        "date_added": 1662988031334,
        "first_ip": "1.1.1.1",
        "ips_count": 16,
        "last_ip": "1.1.1.1",
        "organization_handles": [
            "EH92-RIPE",
            "EASYNET-UK-MNT",
            "AR17615-RIPE",
            "JW372-RIPE"
        ],
        "range_id": "6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5"
    }
]

EXTERNAL_RANGE_RESULTS = [
    {
        "active_responsive_ips_count": 0,
        "business_units": [
            "VanDelay Industries"
        ],
        "date_added": 1662988031334,
        "details": {
            "networkRecords": [
                {
                    "firstIp": "1.1.1.1",
                    "handle": "1.1.1.1 - 1.1.1.1",
                    "lastChanged": 1662987151163,
                    "lastIp": "1.1.1.1",
                    "name": "SEARS-HK",
                    "organizationRecords": [
                        {
                            "address": "",
                            "dateAdded": 1662986267926,
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
                            "address": "HKT Limited\nPO Box 9896 GPO          ",
                            "dateAdded": 1662986267926,
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
                        },
                        {
                            "address": "27/F, PCCW Tower, Taikoo Place,\n979 King's Road, Quarry Bay, HK          ",
                            "dateAdded": 1662986267926,
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
            "TA66-AP",
            "BNA2-AP"
        ],
        "range_id": "4da29b7f-3086-3b52-981b-aa8ee5da1e60"
    }
]

EXTERNAL_EXPOSURES_RESULTS = [
    {
        "agent_id": null,
        "asm_ids": "3c176460-8735-333c-b618-8262e2fb660c",
        "asm_va_score": null,
        "asset_type": "CERTIFICATE",
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
        "name": "*.acme.com",
        "operation_system": null,
        "region": null,
        "sensor": [
            "XPANSE"
        ],
        "service_type": []
    },
    {
        "agent_id": null,
        "asm_ids": "43164fde-8e87-3d1e-8530-82f14cd3ae9a",
        "asm_va_score": null,
        "asset_type": "CERTIFICATE",
        "business_units": [
            "VanDelay Industries"
        ],
        "certificate_algorithm": "SHA256withRSA",
        "certificate_classifications": [
            "Wildcard",
            "Expired"
        ],
        "certificate_issuer": "COMODO",
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
        "name": "*.ch3.intra.kmart.com",
        "operation_system": null,
        "region": null,
        "sensor": [
            "XPANSE"
        ],
        "service_type": []
    }
]

EXTERNAL_EXPOSURE_RESULTS = [
    {
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
        "created": 1662987013779,
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
]

INTERNET_EXPOSURE_POST_FORMAT = [
    {
        "asm_ids": "3c176460-8735-333c-b618-8262e2fb660c",
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
        "asm_ids": "43164fde-8e87-3d1e-8530-82f14cd3ae9a",
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

REMEDIATION_RULES_RESULTS = [
    {
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
]

RCS_START_SCAN_SUCCESSFUL_RESULTS_201 = {
    "scanId": "12345abc-123a-1234-a123-efgh12345678",
    "scan_creation_status": "created"
}

RCS_START_SCAN_SUCCESSFUL_RESULTS_200 = {
    "scanId": "12345abc-123a-1234-a123-efgh12345678",
    "scan_creation_status": "existing"
}

RCS_GET_SCAN_STATUS_SUCCESS_REMEDIATED_RESULTS_200 = {
    "status": "SUCCESS",
    "result": "REMEDIATED"
}

RCS_GET_SCAN_STATUS_SUCCESS_UNREMEDIATED_RESULTS_200 = {
    "status": "SUCCESS",
    "result": "UNREMEDIATED"
}

RCS_GET_SCAN_STATUS_IN_PROGRESS_RESULTS_200 = {
    "status": "IN_PROGRESS",
}

RCS_GET_SCAN_STATUS_FAILED_ERROR_RESULTS_200 = {
    "status": "FAILED_ERROR",
}

RCS_GET_SCAN_STATUS_FAILED_TIMEOUT_RESULTS_200 = {
    "status": "FAILED_TIMEOUT",
}

RCS_GET_SCAN_STATUS_OTHER_RESULTS_200 = {
    "status": "OTHER",
}

ASM_GET_ATTACK_SURFACE_RULE_RESULTS = [
    {
        "attack_surface_rule_id": "RdpServer",
        "attack_surface_rule_name": "RDP Server",
        "category": "Attack Surface Reduction",
        "created": 1698035622000,
        "description": "Remote Desktop Protocol (RDP) servers provide remote access to a computer over a network connection. Externally accessible RDP servers pose a significant security risk as they are frequent targets for attackers and can be vulnerable to a variety of documented exploits.",
        "enabled_status": "ON",
        "knowledge_base_link": None,
        "modified": 1605140275000,
        "modified_by": None,
        "priority": "High",
        "remediation_guidance": "Recommendations to reduce the likelihood of malicious RDP attempts are as follows:\\n\\n1. Best practice is to not have RDP publicly accessible on the Internet and instead only on trusted local networks.\\n2. Implement a risk-based approach that prioritizes patching RDP vulnerabilities that have known weaponized public exploits.\\n3. Limit RDP access to a specific user group and implementing lockout policies is an additional measure to protect against RDP brute-forcing which is another common tactic used by attackers. In addition, enable NLA (Network Level Authentication) which is non-default on older versions.\\n4. If remote access to RDP or terminal services is a business requirement, it should only be made accessible through a secure Virtual Private Network (VPN) connection with multi-factor authentication (MFA) to the corporate network or through a zero-trust remote access gateway."
    }
]
