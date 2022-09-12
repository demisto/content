#adding so null don't get seen as variable.
null = None

EXTERNAL_SERVICES_RESULTS = [
    {
        "active_classifications": [],
        "business_units": [
            "jwilkes - Toys R US"
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
            "104.207.249.74"
        ],
        "is_active": "Inactive",
        "last_observed": 1661357820000,
        "port": 53,
        "protocol": "UDP",
        "service_id": "8b8f9d0a-4acd-3d88-9042-c7d17c2b44e9",
        "service_name": "DNS Server at 104.207.249.74:53",
        "service_type": "DnsServer"
    },
    {
        "active_classifications": [
            "DnsServer",
            "ISCBIND9"
        ],
        "business_units": [
            "jwilkes test - VanDelay Industries"
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
            "112.95.160.91"
        ],
        "is_active": "Active",
        "last_observed": 1662536820000,
        "port": 53,
        "protocol": "UDP",
        "service_id": "7a4ce6ec-9ce3-3002-ac66-862854b2d7f7",
        "service_name": "DNS Server at 112.95.160.91:53",
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
            "jwilkes - Toys R US"
        ],
        "details": {
            "businessUnits": [
                {
                    "name": "jwilkes - Toys R US"
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
            "serviceKey": "52.22.120.51:22",
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
            "52.22.120.51"
        ],
        "is_active": "Active",
        "last_observed": 1662967560000,
        "port": 22,
        "protocol": "TCP",
        "service_id": "94232f8a-f001-3292-aa65-63fa9d981427",
        "service_name": "SSH Server at 52.22.120.51:22",
        "service_type": "SshServer"
    }
]

EXTERNAL_RANGES_RESULTS = [
    {
        "active_responsive_ips_count": 0,
        "business_units": [
            "jwilkes test - VanDelay Industries"
        ],
        "date_added": 1662988031334,
        "first_ip": "220.241.52.192",
        "ips_count": 64,
        "last_ip": "220.241.52.255",
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
            "jwilkes test - VanDelay Industries"
        ],
        "date_added": 1662988031334,
        "first_ip": "217.206.176.80",
        "ips_count": 16,
        "last_ip": "217.206.176.95",
        "organization_handles": [
            "EH92-RIPE",
            "EASYNET-UK-MNT",
            "AR17615-RIPE",
            "JW372-RIPE"
        ],
        "range_id": "6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5"
    }
]