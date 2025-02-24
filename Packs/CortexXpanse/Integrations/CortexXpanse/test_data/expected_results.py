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

LIST_ALERTS_RESULTS = [
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
    },
    {
        "external_id": "FAKE-GUID-3",
        "severity": "high",
        "matching_status": "MATCHED",
        "end_match_attempt_ts": null,
        "local_insert_ts": 1659455246813,
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
        "resolution_status": "STATUS_230_REOPENED",
        "resolution_comment": "ASM alert reopened",
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
        "alert_id": "34",
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

ATTACK_SURFACE_RULES_RESULTS = [
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

TAG_APPLY_RESULTS = "Assignment operation: True"
TAG_REMOVE_RESULTS = "Removal operation: True"

LIST_INCIDENTS_RESULTS = [{
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
}]

INCIDENT_GET_RESULTS = {
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
    "high_severity_alert_count": 1,
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
    "med_severity_alert_count": 1,
    "modification_time": 1696275576460,
    "notes": null,
    "original_tags": [
        "BU:Xpanse VanDelay Demo 3"
    ],
    "resolve_comment": null,
    "resolved_timestamp": null,
    "rule_based_score": 825,
    "severity": "high",
    "starred": True,
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
                "reportedExploitInTheWild": True
            },
            {
                "confidence": "High",
                "cveId": "CVE-2021-34473",
                "cvssScore": 9.800000190734863,
                "epssScore": 0.9732999801635742,
                "exploitMaturity": "Weaponized",
                "matchType": "ExactVersionMatch",
                "mostRecentReportedExploitDate": "2023-10-12",
                "reportedExploitInTheWild": True
            },
            {
                "confidence": "High",
                "cveId": "CVE-2021-34523",
                "cvssScore": 9.800000190734863,
                "epssScore": 0.9726300239562988,
                "exploitMaturity": "Weaponized",
                "matchType": "ExactVersionMatch",
                "mostRecentReportedExploitDate": "2023-10-12",
                "reportedExploitInTheWild": True
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
        "versionMatched": True
    },
    "xpanse_risk_score": 825
}

INCIDENT_UPDATE_RESULTS = "Update operation successful: True"

ALERT_UPDATE_RESULTS = "Updated alerts: [602]"

EXTERNAL_WEBSITES_RESULTS = {
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
            }]
    }
}
