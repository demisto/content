#adding so null don't get seen as variable.
null = None

EXTERNAL_SERVICES_RESPONSE = {
    "reply": {
        "total_count": 5999,
        "result_count": 2,
        "external_services": [
            {
                "service_id": "8b8f9d0a-4acd-3d88-9042-c7d17c2b44e9",
                "service_name": "DNS Server at 104.207.249.74:53",
                "service_type": "DnsServer",
                "ip_address": [
                    "104.207.249.74"
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
                    "jwilkes - Toys R US"
                ],
                "externally_inferred_vulnerability_score": null,
                "externally_inferred_cves": []
            },
            {
                "service_id": "7a4ce6ec-9ce3-3002-ac66-862854b2d7f7",
                "service_name": "DNS Server at 112.95.160.91:53",
                "service_type": "DnsServer",
                "ip_address": [
                    "112.95.160.91"
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
                    "jwilkes test - VanDelay Industries"
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
                "service_name": "SSH Server at 52.22.120.51:22",
                "service_type": "SshServer",
                "ip_address": [
                    "52.22.120.51"
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
                    "jwilkes - Toys R US"
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
                    "serviceKey": "52.22.120.51:22",
                    "serviceKeyType": "IP",
                    "businessUnits": [
                        {
                            "name": "jwilkes - Toys R US"
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
                "first_ip": "220.241.52.192",
                "last_ip": "220.241.52.255",
                "ips_count": 64,
                "active_responsive_ips_count": 0,
                "date_added": 1662988031334,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
                ],
                "organization_handles": [
                    "MAINT-HK-PCCW-BIA-CS",
                    "TA66-AP",
                    "BNA2-AP"
                ]
            },
            {
                "range_id": "6ef4638e-7788-3ef5-98a5-ad5b7f4e02f5",
                "first_ip": "217.206.176.80",
                "last_ip": "217.206.176.95",
                "ips_count": 16,
                "active_responsive_ips_count": 0,
                "date_added": 1662988031334,
                "business_units": [
                    "jwilkes test - VanDelay Industries"
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