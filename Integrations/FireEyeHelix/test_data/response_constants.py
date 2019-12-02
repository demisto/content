ALERT_RESP = {
    "primary_id": 3232,
    "alert_type": {
        "id": 1793,
        "created_at": "2019-05-25T19:40:09.132456Z",
        "updated_at": "2019-08-12T18:40:12.132456Z",
        "type_id": "8916-1b5d68c0519f",
        "category": "Host",
        "detail_fields": [
            "username"
        ],
        "is_default": False,
        "is_internal": True,
        "name": "HX",
        "summary_fields": [
            "malwaretype",
            "virus"
        ],
        "source": [
            "agenthostname",
            "agentip"
        ],
        "destination": [],
        "created_by": "id",
        "updated_by": "id"
    },
    "assigned_to": None,
    "context": None,
    "created_by": {
        "id": "id",
        "avatar": "avatar",
        "name": "System User",
        "username": "system_user",
        "primary_email": "no.reply@fireeye.com"
    },
    "events_count": 2,
    "notes_count": 0,
    "queues": [
        "Default Queue"
    ],
    "source_url": "https://url",
    "updated_by": {
        "id": "id",
        "avatar": "avatar",
        "name": "George",
        "username": "george@demisto.com",
        "primary_email": "george@demisto.com"
    },
    "organization": "demisto",
    "created_at": "2019-03-30T19:40:16.132456Z",
    "updated_at": "2019-10-20T12:35:02.132456Z",
    "id": 123,
    "alert_threat": "Unknown",
    "alert_type_details": {
        "source": "siem",
        "detail": {
            "username": "demon",
            "processpath": "c:\\windows\\microsoft.net\\framework\\v7.0.30319\\csc.exe",
            "confidence": "high",
            "sha1": "sha1",
            "agenthostname": "siem",
            "pid": 11,
            "objecttype": "file",
            "hostname": "helix.apps.fireeye.com",
            "bytes": 35,
            "meta_deviceid": "deviceID",
            "agentip": "192.168.0.1",
            "virus": "gen:variant.ursu",
            "result": "quarantined",
            "malwaretype": "malware",
            "createdtime": "2019-03-30T14:07:53.667Z",
            "lastmodifiedtime": "2019-03-31T14:07:53.778Z",
            "filename": "c:\\users\\demon\\appdata\\local\\temp",
            "accountdomain": "siem",
            "method": "oas",
            "lastaccessedtime": "2019-03-30T14:07:53.217Z",
            "md5": "md5"
        },
        "summary": {
            "virus": "gen:variant.ursu",
            "malwaretype": "malware"
        }
    },
    "assigned_at": None,
    "classification": 30,
    "closed_reason": "",
    "closed_state": "Unknown",
    "confidence": "High",
    "description": "FireEye HX detected and quarantined malware on this system.",
    "distinguisher_key": "quarantined",
    "distinguishers": {
        "virus": "gen:variant.ursu",
        "agentid": "4fkds",
        "result": "quarantined",
        "malwaretype": "malware"
    },
    "emailed_at": 7371,
    "events_threshold": 1,
    "external_id": "",
    "first_event_at": "2019-03-30T14:07:34.132456ZZ",
    "last_event_at": "2019-03-31T14:08:07.132456ZZ",
    "external_ips": [],
    "external_ips_count": 0,
    "info_links": [],
    "internal_ips": [],
    "internal_ips_count": 0,
    "is_suppressed": False,
    "is_threat": False,
    "is_tuned": False,
    "kill_chain": [
        "5 - Installation"
    ],
    "last_sync_ms": 15535426,
    "message": "FIREEYE H",
    "metaclasses": {
        "ids,antivirus": 2
    },
    "mongo_id": "5c99",
    "origin_id": "map_rule",
    "products": {
        "hx": 2
    },
    "risk": "Medium",
    "risk_order": 2,
    "search": "class=fireeye_hx_alert eventlog=mal result=quarantined NOT srcipv4:$exclusions.global.srcipv4",
    "seconds_threshold": 60,
    "severity": "Medium",
    "source_revision": 0,
    "state": "Open",
    "tags": [
        "fireeye"
    ],
    "threat_changed_at": None,
    "threat_type": 50,
    "trigger_id": "2615",
    "trigger_revision": 0,
    "tuning_search": "",
    "type": "fireeye_rule"
}

ALERTS_RESP = {
    "meta": {
        "count": 115,
        "previous": None,
        "limit": 2,
        "offset": 0,
        "next": ""
    },
    "results": [
        {
            "primary_id": 3232,
            "alert_type": {
                "id": 1793,
                "created_at": "2019-05-25T19:40:09.132456Z",
                "updated_at": "2019-08-12T18:40:12.132456Z",
                "type_id": "8916-1b5d68c0519f",
                "category": "Host",
                "detail_fields": [
                    "username"
                ],
                "is_default": False,
                "is_internal": True,
                "name": "HX",
                "summary_fields": [
                    "malwaretype",
                    "virus"
                ],
                "source": [
                    "agenthostname",
                    "agentip"
                ],
                "destination": [],
                "created_by": "id",
                "updated_by": "id"
            },
            "assigned_to": None,
            "context": None,
            "created_by": {
                "id": "id",
                "avatar": "avatar",
                "name": "System User",
                "username": "system_user",
                "primary_email": "no.reply@fireeye.com"
            },
            "events_count": 2,
            "notes_count": 0,
            "queues": [
                "Default Queue"
            ],
            "source_url": "https://url",
            "updated_by": {
                "id": "id",
                "avatar": "avatar",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "george@demisto.com"
            },
            "organization": "demisto",
            "created_at": "2019-03-30T19:40:16.132456Z",
            "updated_at": "2019-10-20T12:35:02.132456Z",
            "id": 123,
            "alert_threat": "Unknown",
            "alert_type_details": {
                "source": "siem",
                "detail": {
                    "username": "demon",
                    "processpath": "c:\\windows\\microsoft.net\\framework\\v7.0.30319\\csc.exe",
                    "confidence": "high",
                    "sha1": "sha1",
                    "agenthostname": "siem",
                    "pid": 11,
                    "objecttype": "file",
                    "hostname": "helix.apps.fireeye.com",
                    "bytes": 35,
                    "meta_deviceid": "deviceID",
                    "agentip": "192.168.0.1",
                    "virus": "gen:variant.ursu",
                    "result": "quarantined",
                    "malwaretype": "malware",
                    "createdtime": "2019-03-30T14:07:53.667Z",
                    "lastmodifiedtime": "2019-03-31T14:07:53.778Z",
                    "filename": "c:\\users\\demon\\appdata\\local\\temp",
                    "accountdomain": "siem",
                    "method": "oas",
                    "lastaccessedtime": "2019-03-30T14:07:53.217Z",
                    "md5": "md5"
                },
                "summary": {
                    "virus": "gen:variant.ursu",
                    "malwaretype": "malware"
                }
            },
            "assigned_at": None,
            "classification": 30,
            "closed_reason": "",
            "closed_state": "Unknown",
            "confidence": "High",
            "description": "FireEye HX detected and quarantined malware on this system.",
            "distinguisher_key": "quarantined",
            "distinguishers": {
                "virus": "gen:variant.ursu",
                "agentid": "4fkds",
                "result": "quarantined",
                "malwaretype": "malware"
            },
            "emailed_at": 7371,
            "events_threshold": 1,
            "external_id": "",
            "first_event_at": "2019-03-30T14:07:34.132456ZZ",
            "last_event_at": "2019-03-31T14:08:07.132456ZZ",
            "external_ips": [],
            "external_ips_count": 0,
            "info_links": [],
            "internal_ips": [],
            "internal_ips_count": 0,
            "is_suppressed": False,
            "is_threat": False,
            "is_tuned": False,
            "kill_chain": [
                "5 - Installation"
            ],
            "last_sync_ms": 15535426,
            "message": "FIREEYE H",
            "metaclasses": {
                "ids,antivirus": 2
            },
            "mongo_id": "5c99",
            "origin_id": "map_rule",
            "products": {
                "hx": 2
            },
            "risk": "Medium",
            "risk_order": 2,
            "search": "class=fireeye_hx_alert eventlog=mal result=quarantined NOT srcipv4:$exclusions.global.srcipv4",
            "seconds_threshold": 60,
            "severity": "Medium",
            "source_revision": 0,
            "state": "Open",
            "tags": [
                "fireeye"
            ],
            "threat_changed_at": None,
            "threat_type": 50,
            "trigger_id": "2615",
            "trigger_revision": 0,
            "tuning_search": "",
            "type": "fireeye_rule"
        },
        {
            "primary_id": 23,
            "alert_type": {
                "id": 18,
                "created_at": "2019-03-25T10:40:09.132456Z",
                "updated_at": "2019-09-10T18:40:13.132456Z",
                "type_id": "03e1099a-38d8",
                "category": "Host",
                "detail_fields": [
                    "eventtime"
                ],
                "is_default": False,
                "is_internal": True,
                "name": "HX",
                "summary_fields": [
                    "result",
                    "iocnames"
                ],
                "source": [
                    "agenthostname",
                    "agentip"
                ],
                "destination": [],
                "created_by": "ab",
                "updated_by": "ab"
            },
            "assigned_to": None,
            "context": None,
            "created_by": {
                "id": "ab",
                "avatar": "avatar",
                "name": "System User",
                "username": "system_user",
                "primary_email": "no.reply@fireeye.com"
            },
            "events_count": 2,
            "notes_count": 0,
            "queues": [
                "Default Queue"
            ],
            "source_url": "https://source_url.com",
            "updated_by": {
                "id": "e7",
                "avatar": "avatar",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "george@demisto.com"
            },
            "organization": "",
            "created_at": "2019-03-30T19:40:17.132456Z",
            "updated_at": "2019-10-23T20:35:02.132456Z",
            "id": 32,
            "alert_threat": "Unknown",
            "alert_type_details": {
                "source": "siem",
                "detail": {
                    "username": "system",
                    "processpath": "c:\\windows\\system32\\cmd.exe",
                    "eventtime": "2019-03-30T14:11:31.000Z",
                    "hostname": "helix.apps.fireeye.com",
                    "iocnames": "cobalt strike",
                    "process": "cmd.exe",
                    "args": "cmd.exe /c echo zhfrlb",
                    "pid": 99,
                    "agentip": "192.168.0.1",
                    "meta_deviceid": "86",
                    "result": "alert",
                    "starttime": "2019-03-30T14:11:20.002Z",
                    "pprocess": "services.exe",
                    "ppid": 66,
                    "agenthostname": "siem",
                    "md5": "md5"
                },
                "summary": {
                    "result": "alert",
                    "iocnames": "cobalt strike"
                }
            },
            "assigned_at": None,
            "classification": 2,
            "closed_reason": "",
            "closed_state": "Unknown",
            "confidence": "High",
            "description": "This rule alerts on IOC.",
            "distinguisher_key": "cobalt strike",
            "distinguishers": {
                "agentid": "fw",
                "iocnames": "cobalt strike"
            },
            "emailed_at": 737100,
            "events_threshold": 1,
            "external_id": "",
            "first_event_at": "2019-03-25T14:09:45.132456Z",
            "last_event_at": "2019-03-25T14:11:31.132456Z",
            "external_ips": [],
            "external_ips_count": 0,
            "info_links": [],
            "internal_ips": [],
            "internal_ips_count": 0,
            "is_suppressed": False,
            "is_threat": False,
            "is_tuned": False,
            "kill_chain": [
                "5 - Installation"
            ],
            "last_sync_ms": 1553542006849,
            "message": "FIREEYE HX [IOC Process Event]",
            "metaclasses": {
                "ids": 2
            },
            "mongo_id": "5c",
            "origin_id": "map_rule",
            "products": {
                "hx": 2
            },
            "risk": "Medium",
            "risk_order": 2,
            "search": "class=fireeye_hx_alert eventlog=ioc eventtype=processevent NOT srcipv4:$exclusions.global.srcipv4",
            "seconds_threshold": 60,
            "severity": "Medium",
            "source_revision": 0,
            "state": "Open",
            "tags": [
                "fireeye",
                "helixhxrule"
            ],
            "threat_changed_at": None,
            "threat_type": 50,
            "trigger_id": "42399",
            "trigger_revision": 0,
            "tuning_search": "",
            "type": "fireeye_rule"
        }
    ]
}

CASES_BY_ALERT_RESP = {
    "meta": {
        "count": 1,
        "previous": None,
        "limit": 30,
        "offset": 0,
        "next": None
    },
    "results": [
        {
            "assigned_to": None,
            "created_at": "created_at",
            "created_by": {
                "id": "id",
                "avatar": "avatar",
                "name": "name",
                "username": "username",
                "primary_email": "primary_email"
            },
            "description": "",
            "events_count": 10,
            "id": 35,
            "info_links": [],
            "name": "demisto test case",
            "notes_count": 0,
            "priority": "Critical",
            "priority_order": 4,
            "severity": 10,
            "state": "Testing",
            "status": "Declared",
            "tags": [],
            "total_days_unresolved": "16 23:52:09.819390",
            "updated_at": "updated_at",
            "updated_by": {
                "id": "id",
                "avatar": "avatar",
                "name": "name",
                "username": "username",
                "primary_email": "primary_email"
            }
        }
    ]
}

ENDPOINTS_BY_ALERT_RESP = {
    "meta": {
        "count": 1,
        "previous": None,
        "limit": 30,
        "offset": 0,
        "next": None
    },
    "results": {
        "status": "completed",
        "endpoints": [
            {
                "id": 191,
                "customer_id": "demisto",
                "agent_id": "agent_id",
                "containment_queued": False,
                "containment_state": "normal",
                "created_at": "created_at",
                "device_id": "device_id",
                "domain": "WORKGROUP",
                "hostname": "Demisto",
                "mac_address": "mac_address",
                "operating_system": "Windows 10 Pro",
                "primary_ip_address": "primary_ip_address",
                "updated_at": "updated_at",
                "timezone": "timezone",
                "hash": "hash",
                "source_url": "source_url"
            }
        ]
    }
}

EVENTS_BY_ALERT_RESP = {
    "meta": {
        "count": 10,
        "previous": None,
        "limit": 1,
        "offset": 0,
        "next": ""
    },
    "results": [
        {
            "username": "admin",
            "_eventid": "",
            "process": "net1",
            "agenturi": "/hx/api/v3/hosts/f9zsksax",
            "pid": 404,
            "matched_at": "2019-08-11t06:51:40.000z",
            "pprocesspath": "c:\\windows\\system32\\net1",
            "result": "alert",
            "meta_ts": "2019-09-11T06:51:40.000Z",
            "processpath": "c:\\windows\\system32\\net1.exe",
            "_errors": [],
            "meta_agenturi": "/hx/api/v3/hosts/f9zsksax",
            "meta_rule": "fireeye_hx_alert",
            "indicator": {
                "category": "custom",
                "display_name": "tactic",
                "url": "/hx/api/v3/indicators/custom/f9zsksax",
                "signature": None,
                "_id": "f9zsksax",
                "uri_name": "f9zsksax"
            },
            "uuid": "f9zsksax",
            "eventlog": "ioc",
            "reported_at": "2019-09-13t06:53:08.000",
            "eventtype": "processevent",
            "msr_ruleids": [],
            "agentstatus": "normal",
            "condition": {
                "indicators": [
                    {
                        "category": "custom",
                        "name": "tactic",
                        "signature": None
                    }
                ]
            },
            "hx_alert_id": 859,
            "detect_rulematches": [
                {
                    "confidence": "high",
                    "severity": "medium",
                    "ruleid": "99",
                    "tags": [
                        "fireeye",
                        "helixhxrule",
                        "ioc"
                    ],
                    "rulename": "fireeye hx",
                    "revision": 0
                },
                {
                    "confidence": "medium",
                    "severity": "medium",
                    "ruleid": "1",
                    "tags": [],
                    "rulename": "test",
                    "revision": 0
                }
            ],
            "alerturi": "f9zsksax==",
            "ppid": 142,
            "metaclass": "ids",
            "eventid": "101",
            "eventtime": "2019-09-13T06:51:59.000Z",
            "iocnames": "tactic",
            "md5values": [
                "md5"
            ],
            "uri_parsed": "uri",
            "args": "c:\\windows\\system32\\net1",
            "detect_ruleids": [
                "99"
            ],
            "agentdetails": {
                "containmentState": "normal",
                "appStarted": "2019-09-10t05:41:17z",
                "regOwner": "george",
                "ProRemSvcStatus": "running",
                "ProcessTrackerStatus": "disabled",
                "configId": "sljlx==",
                "timezone": "",
                "productID": "00311",
                "totalphysical": "170053200",
                "ExdPluginStatus": "running",
                "uptime": "pt3514s",
                "installDate": "2019-07-08t13:28:00z",
                "MalwareProtectionStatus": "running",
                "@created": "2019-09-13t06:22:12z",
                "KernelServices": {
                    "Status": "loaded"
                },
                "procConfigInfo": {
                    "lpcDevice": "intel",
                    "iommu": "enabled",
                    "virtualization": "enabled",
                    "vmGuest": "no"
                },
                "appVersion": "30.0",
                "machine": "desktop",
                "platform": "win",
                "configChannel": "6430f3d0aea8",
                "stateAgentStatus": "ok",
                "intelVersion": "101",
                "biosInfo": {
                    "biosVersion": "dell inc.",
                    "biosDate": "05/09/2009",
                    "biosType": "uefi"
                },
                "appCreated": "2019-07-21t16:00:05z",
                "networkArray": {
                    "networkInfo": [
                        {
                            "ipArray": {
                                "ipInfo": [
                                    {
                                        "ipv6Address": "1:1:1:1"
                                    },
                                    {
                                        "ipAddress": "192.168.0.1"
                                    }
                                ]
                            },
                            "MAC": "MAC",
                            "adapter": "{adapter}",
                            "description": "pangp virtual #2"
                        },
                        {
                            "ipArray": {
                                "ipInfo": [
                                    {
                                        "ipv6Address": "1:1:1:1"
                                    },
                                    {
                                        "subnetMask": "255.255.0.0",
                                        "ipAddress": "192.168.0.1"
                                    }
                                ]
                            },
                            "MAC": "mac",
                            "adapter": "{}",
                            "description": "npcap loopback adapter"
                        },
                        {
                            "ipArray": {
                                "ipInfo": [
                                    {
                                        "ipv6Address": "1:1:1:1"
                                    },
                                    {
                                        "subnetMask": "255.255.255.0",
                                        "ipAddress": "192.168.0.1"
                                    }
                                ]
                            },
                            "MAC": "mac",
                            "adapter": "{}",
                            "description": "virtualbox host"
                        },
                        {
                            "ipArray": {
                                "ipInfo": [
                                    {
                                        "ipv6Address": "1:1:1:1"
                                    },
                                    {
                                        "ipAddress": "192.168.0.1"
                                    }
                                ]
                            },
                            "MAC": "mac",
                            "adapter": "{}",
                            "description": "microsoft wi-fi"
                        },
                        {
                            "ipArray": {
                                "ipInfo": [
                                    {
                                        "ipv6Address": "1:1:1:1"
                                    },
                                    {
                                        "ipAddress": "192.168.0.1"
                                    }
                                ]
                            },
                            "MAC": "mac",
                            "adapter": "{}",
                            "description": "microsoft wi-fi"
                        },
                        {
                            "dhcpLeaseObtained": "2019-09-13t06:50:36z",
                            "description": "vmware virtual ethernet",
                            "adapter": "{}",
                            "MAC": "mac",
                            "dhcpServerArray": {
                                "dhcpServer": [
                                    "192.168.0.1"
                                ]
                            },
                            "dhcpLeaseExpires": "2019-09-13t07:23:36z",
                            "ipArray": {
                                "ipInfo": [
                                    {
                                        "ipv6Address": "1:1:1:1"
                                    },
                                    {
                                        "subnetMask": "255.255.255.0",
                                        "ipAddress": "192.168.0.1"
                                    }
                                ]
                            }
                        },
                        {
                            "dhcpLeaseObtained": "2019-09-11t11:18:59z",
                            "ipGatewayArray": {
                                "ipGateway": [
                                    "192.168.0.1"
                                ]
                            },
                            "description": "intel(r) dual band",
                            "adapter": "{}",
                            "MAC": "mac",
                            "dhcpServerArray": {
                                "dhcpServer": [
                                    "192.168.0.1"
                                ]
                            },
                            "dhcpLeaseExpires": "2019-01-19t16:18:59z",
                            "ipArray": {
                                "ipInfo": [
                                    {
                                        "subnetMask": "255.255.255.0",
                                        "ipAddress": "192.168.0.1"
                                    }
                                ]
                            }
                        },
                        {
                            "ipArray": {
                                "ipInfo": [
                                    {
                                        "ipv6Address": "1:1:1:1"
                                    },
                                    {
                                        "ipAddress": "192.168.0.1"
                                    }
                                ]
                            },
                            "MAC": "mac",
                            "adapter": "{}",
                            "description": "bluetooth device"
                        },
                        {
                            "ipArray": {
                                "ipInfo": [
                                    {
                                        "ipv6Address": "1:1:1:1"
                                    },
                                    {
                                        "ipAddress": "192.168.0.1"
                                    }
                                ]
                            },
                            "adapter": "{}",
                            "description": "software loopback interface 1"
                        }
                    ]
                },
                "drives": "c:,g:",
                "intelTimestamp": "2019-01-12t06:51:20z",
                "malware": {
                    "mg": {
                        "engine": {
                            "version": "30.19"
                        },
                        "content": {
                            "updated": "2019-01-16t06:12:55z",
                            "version": "14"
                        }
                    },
                    "UserFPExclusionsContentVersion": "0.0.0",
                    "DTIExclusionsContentVersion": "1.13.5",
                    "UserFPExclusionsSchemaVersion": "1.0.0",
                    "version": "30.17.0",
                    "QuarantineStatus": "cleanenabled",
                    "av": {
                        "engine": {
                            "version": "11.0"
                        },
                        "content": {
                            "updated": "2019-09-11t04:52:56z",
                            "version": "7"
                        }
                    },
                    "config": {
                        "mg": {
                            "status": "enabled",
                            "quarantine": {
                                "status": "enabled"
                            }
                        },
                        "av": {
                            "status": "enabled",
                            "quarantine": {
                                "status": "cleanenabled"
                            }
                        }
                    },
                    "DTIExclusionsSchemaVersion": "1.0.0"
                },
                "buildNumber": "18",
                "FIPS": "disabled",
                "user": "system",
                "date": "2019-09-13T06:52:57.000Z",
                "productName": "windows 10 home",
                "gmtoffset": "+p",
                "intelETag": "v1",
                "ExdPlugin": {
                    "engine": {
                        "version": "300"
                    },
                    "content-rules": {
                        "version": "3.6"
                    },
                    "content-whitelist": {
                        "version": "1.6"
                    },
                    "version": "30.6"
                },
                "OSbitness": "64-bit",
                "procType": "multiprocessor free",
                "primaryIpv4Address": "192.168.0.1",
                "timezoneDST": "",
                "EventorStatus": "running",
                "availphysical": "4666",
                "timezoneStandard": "",
                "configETag": "v1/156",
                "directory": "c:\\windows\\system32",
                "processor": "intel(r) core(tm)",
                "clockSkew": "+pts"
            },
            "meta_deviceid": "",
            "agentdomain": "workgroup",
            "pprocess": "net.exe",
            "is_false_positive": False,
            "class": "fireeye_hx_alert",
            "agentos": "windows 10 home 18362",
            "md5": "md5",
            "agentmac": "mac",
            "__metadata__": {
                "raw_batch_id": "ed5b3525b0c4",
                "data_type": "passthrough",
                "disable_index": False,
                "dynamic_taxonomy": True,
                "num_events": 1,
                "source_type": "json",
                "target_index": "alerts",
                "batch_id": "ee7d3ebbed5b3525b0c4",
                "customer_id": "",
                "id": "9-09-12",
                "sequence_number": 0
            },
            "agentloggedonusers": "font driver host",
            "conditionid": "jjvnefleq==",
            "uri": "",
            "detect_rulenames": [
                "fireeye hx [ioc process event]",
                "test"
            ],
            "agentip": "192.168.0.1",
            "subtype": "None",
            "deviceid": "759c",
            "starttime": "2019-09-13T06:51:59.276Z",
            "agentid": "hcldmjf9zfmwxov9",
            "agenthostname": "dm1ps9",
            "meta_agentid": "hczFMWXOV9",
            "event_values": {
                "processEvent/processCmdLine": "c:\\windows\\system32\\net1",
                "processEvent/parentPid": 14,
                "processEvent/md5": "md5",
                "processEvent/processPath": "c:\\windows\\system32\\net1",
                "processEvent/parentProcess": "net",
                "processEvent/timestamp": "2019-09-13t06:51:59.276z",
                "processEvent/startTime": "2019-09-13t06:51:59.276z",
                "processEvent/process": "net1.exe",
                "processEvent/username": "desktop-54m",
                "processEvent/pid": 400,
                "processEvent/parentProcessPath": "c:\\windows\\system32\\net.exe",
                "processEvent/eventType": "start"
            }
        }
    ]
}

NOTES_GET_RESP = {
    "meta": {
        "count": 2,
        "previous": None,
        "limit": 30,
        "offset": 0,
        "next": None
    },
    "results": [
        {
            "created_by": {
                "id": "a",
                "avatar": "avatar",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "george@demisto.com"
            },
            "created_at": "2019-10-28T07:41:30.396000Z",
            "id": 9,
            "updated_at": "2019-10-28T07:41:42.000123Z",
            "note": "This is a note test"
        },
        {
            "created_by": {
                "id": "a",
                "avatar": "avatar",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "george@demisto.com"
            },
            "created_at": "2019-10-24T13:52:19.021299Z",
            "id": 91,
            "updated_at": "2019-10-24T13:52:19.021399Z",
            "note": "What a great note this is"
        }
    ]
}

NOTES_CREATE_RESP = {
    "created_by": {
        "id": "a",
        "avatar": "avatar",
        "name": "George",
        "username": "george@demisto.com",
        "primary_email": "george@demisto.com"
    },
    "created_at": "2019-10-28T07:41:30.396000Z",
    "id": 9,
    "updated_at": "2019-10-28T07:41:42.000123Z",
    "note": "This is a note test"
}

LIST_SINGLE_ITEM_RESP = {
    "id": 163,
    "value": "aTest list",
    "type": "misc",
    "risk": "Medium",
    "notes": "test ok",
    "list": 3232
}

LIST_ITEMS_RESP = {
    "meta": {
        "count": 1,
        "previous": None,
        "limit": 30,
        "offset": 0,
        "next": None
    },
    "results": [
        {
            "id": 163,
            "value": "Test list",
            "type": "misc",
            "risk": "Low",
            "notes": "",
            "list": 3232
        }
    ]
}

SEARCH_MULTI_RESP = {
    "dsl": {
        "from": 0,
        "aggs": {
            "groupby:subject": {
                "meta": {
                    "field": "subject",
                    "type": "groupby"
                },
                "terms": {
                    "field": "subject.raw",
                    "order": {
                        "_count": "desc"
                    },
                    "min_doc_count": 1,
                    "size": 50
                }
            }
        },
        "terminate_after": 1,
        "directives": {
            "scroll_id": "",
            "page_size": 2,
            "start": "2019-10-28T08:00:00.000Z",
            "highlight_terms": [],
            "limit": 1,
            "timeout": 120000,
            "offset": 0,
            "indices": [
                "events",
                "alerts",
                "appliance_health"
            ],
            "end": "2019-10-29T08:36:16.947Z",
            "search_customer_ids": [
                "demisto"
            ],
            "customer_id": "demisto",
            "scroll": False
        },
        "timeout": "120000ms",
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "meta_ts": {
                                "gte": "2019-10-28T08:00:00.000Z",
                                "lte": "2019-10-29T08:36:16.947Z"
                            }
                        }
                    },
                    {
                        "common": {
                            "domain": {
                                "cutoff_frequency": 0.001,
                                "query": "google.com",
                                "high_freq_operator": "and",
                                "low_freq_operator": "and"
                            }
                        }
                    }
                ]
            }
        },
        "size": 2
    },
    "highlight_terms": None,
    "options": {
        "disable_regex": False,
        "default_timestamp": "meta_ts",
        "analyzer_impl": "legacy",
        "indices": [
            "events",
            "alerts",
            "appliance_health"
        ],
        "quick_mode": True,
        "filters": [],
        "offset": 0,
        "default_field": "rawmsg",
        "use_terminate_after": True,
        "scroll": False,
        "page_size": 10,
        "groupby": {
            "threshold": 1,
            "separator": "|%$,$%|",
            "size": 50
        },
        "search_customer_ids": [
            "demisto"
        ],
        "limit": -1,
        "list_type": "indicator",
        "es6_compatible": True,
        "use_limit_filters": False,
        "customer_id": "demisto",
        "script_impl": "native"
    },
    "mql": "domain:google.com and meta_ts>=2019-10-25T09:07:43.810Z {page_size:2 offset:1 limit:1} | groupby subject sep=`|%$,$%|`",  # noqa: E501
    "results": {
        "hits": {
            "hits": [
                {
                    "_score": 0.0,
                    "_type": "event",
                    "_id": "demisto",
                    "_source": {
                        "status": "delivered",
                        "domain": "mx.google.com",
                        "_eventid": "demisto",
                        "rawmsg": "raw_msg",
                        "meta_cbname": "helix-etp_stats",
                        "srcipv4": "8.8.8.8",
                        "meta_ts": "2019-10-28T10:49:27.210Z",
                        "srclongitude": -122.0785140991211,
                        "size": "21.23",
                        "srccountry": "united states",
                        "eventtype": "trace",
                        "srccity": "mountain view",
                        "to": "demisto@demisto.com",
                        "srclatitude": 37.40599060058594,
                        "subject": "google",
                        "metaclass": "email",
                        "eventid": "demisto",
                        "inreplyto": "demisto",
                        "eventtime": "2019-10-28T10:43:11.000Z",
                        "srcregion": "california",
                        "meta_oml": 1036,
                        "class": "fireeye_etp",
                        "mailfrom": "de@demisto.com",
                        "rawmsghostname": "helix-etp_stats-demisto-etp_stats",
                        "__metadata__": {
                            "raw_batch_id": "demisto",
                            "data_type": "passthrough",
                            "disable_index": False,
                            "dynamic_taxonomy": False,
                            "num_events": 1,
                            "source_type": "json",
                            "target_index": "",
                            "batch_id": "demisto",
                            "customer_id": "demisto",
                            "id": "demisto",
                            "sequence_number": 0
                        },
                        "srcdomain": "google.com",
                        "srcisp": "google llc",
                        "srcusagetype": "dch",
                        "srccountrycode": "us",
                        "meta_rts": "2019-10-28T10:49:27.000Z",
                        "meta_cbid": 99999
                    },
                    "_index": "2019-10-28t00:00:00.000z"
                },
                {
                    "_score": 0.0,
                    "_type": "event",
                    "_id": "demisto",
                    "_source": {
                        "status": "delivered",
                        "domain": "gmr-mx.google.com",
                        "_eventid": "demisto",
                        "rawmsg": "demisto",
                        "meta_cbname": "helix-etp_stats",
                        "srcipv4": "8.8.8.8",
                        "meta_ts": "2019-10-29T05:13:24.009Z",
                        "srclongitude": -122.0785140991211,
                        "size": "315.29",
                        "srccountry": "united states",
                        "eventtype": "trace",
                        "srccity": "mountain view",
                        "to": "demisto@demisto.com",
                        "srclatitude": 37.40599060058594,
                        "subject": "Demisto subj",
                        "metaclass": "email",
                        "eventid": "demisto",
                        "inreplyto": "demisto@demisto.com",
                        "eventtime": "2019-10-29T05:08:39.000Z",
                        "srcregion": "california",
                        "meta_oml": 1178,
                        "class": "fireeye_etp",
                        "mailfrom": "dem@demisto.com",
                        "rawmsghostname": "helix-etp_stats-demisto-etp_stats",
                        "__metadata__": {
                            "raw_batch_id": "demisto",
                            "data_type": "passthrough",
                            "disable_index": False,
                            "dynamic_taxonomy": False,
                            "num_events": 4,
                            "source_type": "json",
                            "target_index": "",
                            "batch_id": "demisto",
                            "customer_id": "demisto",
                            "id": "demisto",
                            "sequence_number": 1
                        },
                        "srcdomain": "google.com",
                        "srcisp": "google llc",
                        "srcusagetype": "dch",
                        "srccountrycode": "us",
                        "meta_rts": "2019-10-29T05:13:24.000Z",
                        "meta_cbid": 99999
                    },
                    "_index": "2019-10-29t00:00:00.000z"
                }
            ],
            "total": 11,
            "max_score": 0.0
        },
        "_shards": {
            "successful": 66,
            "failed": 0,
            "total": 66
        },
        "took": 3046,
        "aggregations": {
            "groupby:subject": {
                "buckets": [
                    {
                        "key": "google alert - gold",
                        "doc_count": 3
                    },
                    {
                        "key": "accepted: meeting",
                        "doc_count": 1
                    },
                    {
                        "key": "invitation: Declined",
                        "doc_count": 1
                    }
                ],
                "meta": {
                    "field": "subject",
                    "type": "groupby"
                },
                "sum_other_doc_count": 0,
                "doc_count_error_upper_bound": 0
            }
        },
        "metrics": {
            "load": 2.8539999999999996,
            "regex": False,
            "list": False,
            "aggregation": True,
            "subsearch": False
        },
        "terminated_early": True,
        "timed_out": False,
        "failures": []
    }
}

SEARCH_ARCHIVE_RESP = {
    "meta": {
        "totalCount": 2,
        "limit": 30,
        "offset": 0
    },
    "data": [
        {
            "_createdBy": {
                "id": "demisto",
                "avatar": "avatar",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "demisto@demisto.com"
            },
            "_updatedBy": {
                "id": "demisto",
                "avatar": "avatar",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "demisto@demisto.com"
            },
            "completeAfterCount": 0,
            "completeAfterDuration": 0,
            "createDate": "2019-10-09T11:19:38.253848Z",
            "customer_id": "demisto",
            "emailNotify": False,
            "errors": [],
            "id": "82",
            "is_part_of_report": False,
            "name": "",
            "numResults": 457,
            "percentComplete": 100.0,
            "query": "domain:[google,com] | groupby eventtype",
            "queryAST": "{}",
            "searchEndDate": "2019-10-09T11:19:00Z",
            "searchStartDate": "2019-10-09T11:19:00Z",
            "sourceBucket": "",
            "state": "completed",
            "timeRemaining": 0.0,
            "updateDate": "2019-10-09T11:19:00.686503Z"
        },
        {
            "_createdBy": {
                "id": "demisto",
                "avatar": "avatar",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "demisto@demisto.com"
            },
            "_updatedBy": {
                "id": "demisto",
                "avatar": "avatar",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "demisto@demisto.com"
            },
            "completeAfterCount": 0,
            "completeAfterDuration": 0,
            "createDate": "2019-10-09T11:18:52.250000Z",
            "customer_id": "demisto",
            "emailNotify": False,
            "errors": [],
            "id": "83",
            "is_part_of_report": False,
            "name": "",
            "numResults": 20,
            "percentComplete": 100.0,
            "query": "domain:[google] | groupby eventtype",
            "queryAST": "{}",
            "searchEndDate": "2019-10-09T11:18:28Z",
            "searchStartDate": "2019-10-09T11:18:28Z",
            "sourceBucket": "",
            "state": "completed",
            "timeRemaining": 0.0,
            "updateDate": "2019-10-09T11:19:21.916006Z"
        }
    ]
}

SEARCH_AGGREGATIONS_SINGLE_RESP = {
    "groupby:subject": {
        "buckets": [
            {
                "key": "Test 1",
                "doc_count": 1
            },
            {
                "key": "Test 2",
                "doc_count": 2
            },
            {
                "key": "Test 3",
                "doc_count": 3
            },
            {
                "key": "Test 4",
                "doc_count": 4
            }
        ],
        "meta": {
            "field": "subject",
            "type": "groupby"
        }
    }
}

SEARCH_ARCHIVE_RESULTS_RESP = {
    "data": [
        {
            "_createdBy": {
                "id": "demisto",
                "avatar": "demisto",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "george@demisto.com"
            },
            "_updatedBy": {
                "id": "demisto",
                "avatar": "demisto",
                "name": "George",
                "username": "george@demisto.com",
                "primary_email": "george@demisto.com"
            },
            "completeAfterCount": 0,
            "completeAfterDuration": 0,
            "createDate": "2019-10-06T11:18:38.253848Z",
            "customer_id": "demisto",
            "emailNotify": False,
            "_errors": [],
            "errors": [],
            "id": "82",
            "is_part_of_report": False,
            "name": "",
            "numResults": 457,
            "percentComplete": 100.0,
            "query": "domain:[google,com] | groupby eventtype",
            "queryAST": "{}",
            "searchEndDate": "2019-10-06T11:18:28Z",
            "searchStartDate": "2019-10-05T11:18:28Z",
            "sourceBucket": "",
            "state": "completed",
            "timeRemaining": 0.0,
            "updateDate": "2019-10-06T11:18:54.686503Z"
        }
    ],
    "results": {
        "dsl": {
            "from": 0,
            "aggs": {
                "groupby:eventtype": {
                    "meta": {
                        "field": "eventtype",
                        "type": "groupby"
                    },
                    "terms": {
                        "field": "eventtype",
                        "order": {
                            "_count": "desc"
                        },
                        "min_doc_count": 1,
                        "size": 50
                    }
                }
            },
            "terminate_after": -1,
            "directives": {
                "scroll_id": "",
                "page_size": 10,
                "start": "2019-10-28T15:00:00.000Z",
                "highlight_terms": [],
                "limit": -1,
                "timeout": 120000,
                "offset": 0,
                "indices": [
                    "events",
                    "alerts",
                    "appliance_health"
                ],
                "end": "2019-10-29T15:40:48.571Z",
                "search_customer_ids": None,
                "customer_id": "",
                "scroll": False
            },
            "timeout": "120000ms",
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "meta_ts": {
                                    "gte": "2019-10-28T15:00:00.000Z",
                                    "lte": "2019-10-29T15:40:48.571Z"
                                }
                            }
                        }
                    ],
                    "minimum_should_match": 1,
                    "should": [
                        {
                            "common": {
                                "domain": {
                                    "cutoff_frequency": 0.001,
                                    "query": "google",
                                    "high_freq_operator": "and",
                                    "low_freq_operator": "and"
                                }
                            }
                        },
                        {
                            "common": {
                                "domain": {
                                    "cutoff_frequency": 0.001,
                                    "query": "com",
                                    "high_freq_operator": "and",
                                    "low_freq_operator": "and"
                                }
                            }
                        }
                    ]
                }
            },
            "size": 10
        },
        "mql": "domain:[google,com] | groupby eventtype sep=`|%$,$%|`",
        "results": {
            "hits": {
                "stored": 457,
                "hits": [
                    {
                        "_type": "event",
                        "_id": "demisto",
                        "_source": {
                            "status": "delivered",
                            "domain": "domain.com",
                            "_eventid": "demsito",
                            "rawmsg": "{}",
                            "meta_cbname": "helix-etp",
                            "srcipv4": "8.8.8.8",
                            "meta_ts": "2019-10-06T10:55:26.103Z",
                            "srclongitude": -0.1257400,
                            "size": "40.04",
                            "srccountry": "",
                            "eventtype": "trace",
                            "srccity": "london",
                            "to": "demisto@demisto.com",
                            "srclatitude": 51.8594,
                            "subject": "dictation users",
                            "metaclass": "email",
                            "eventid": "evenid",
                            "inreplyto": "squidward <squidward@demisto.com>",
                            "eventtime": "2019-10-06T10:48:13.000Z",
                            "srcregion": "",
                            "meta_oml": 908,
                            "class": "fireeye_etp",
                            "mailfrom": "squidward@demisto.com",
                            "rawmsghostname": "helix-etp_stats-etp_stats",
                            "__metadata__": {
                                "raw_batch_id": "",
                                "data_type": "passthrough",
                                "disable_index": False,
                                "dynamic_taxonomy": False,
                                "num_events": 10,
                                "source_type": "json",
                                "target_index": "",
                                "batch_id": "",
                                "customer_id": "",
                                "id": "",
                                "sequence_number": 1
                            },
                            "srcdomain": "",
                            "srcisp": "",
                            "srcusagetype": "",
                            "srccountrycode": "",
                            "meta_rts": "2019-10-06T10:55:26.000Z",
                            "meta_cbid": 99999
                        },
                        "_index": "archive"
                    },
                    {
                        "_type": "event",
                        "_id": "demisto",
                        "_source": {
                            "status": "delivered",
                            "domain": "demisto.com",
                            "_eventid": "",
                            "rawmsg": "{}",
                            "meta_cbname": "helix-etp_stats",
                            "srcipv4": "8.8.8.8",
                            "meta_ts": "2019-10-06T11:09:25.946Z",
                            "srclongitude": -75.19625,
                            "size": "10.75",
                            "srccountry": "",
                            "eventtype": "trace",
                            "srccity": "cha",
                            "to": "squidward@demisto.com",
                            "srclatitude": 40.282958,
                            "subject": "meet world",
                            "metaclass": "email",
                            "eventid": "demisto",
                            "inreplyto": "\"squidward\" <fsquidward@demisto.com>",
                            "eventtime": "2019-10-06T11:02:01.000Z",
                            "srcregion": "penn",
                            "meta_oml": 1160,
                            "class": "fireeye_etp",
                            "mailfrom": "squidward@demisto.com",
                            "rawmsghostname": "helix-etp_stats-etp_stats",
                            "__metadata__": {
                                "raw_batch_id": "demisto",
                                "data_type": "passthrough",
                                "disable_index": False,
                                "dynamic_taxonomy": False,
                                "num_events": 5,
                                "source_type": "json",
                                "target_index": "",
                                "batch_id": "",
                                "customer_id": "",
                                "id": "",
                                "sequence_number": 0
                            },
                            "srcdomain": "squidward.com",
                            "srcisp": "squidward",
                            "srcusagetype": "com",
                            "srccountrycode": "us",
                            "meta_rts": "2019-10-06T11:09:25.000Z",
                            "meta_cbid": 99999
                        },
                        "_index": "archive"
                    },
                    {
                        "_type": "event",
                        "_id": "demisto",
                        "_source": {
                            "status": "delivered",
                            "domain": "demisto.com",
                            "_eventid": "demiostop",
                            "rawmsg": "{}",
                            "meta_cbname": "helix-etp_stats",
                            "srcipv4": "8.8.8.8",
                            "meta_ts": "2019-10-06T11:09:25.946Z",
                            "srclongitude": -93.119,
                            "size": "26.92",
                            "srccountry": "united states",
                            "eventtype": "trace",
                            "srccity": "",
                            "to": "squidward@demisto.com",
                            "srclatitude": 33.50,
                            "subject": "fw: reminder",
                            "metaclass": "email",
                            "eventid": "dwasdkffv",
                            "inreplyto": "squidward <squidward@demisto.com>",
                            "eventtime": "2019-10-06T11:02:18.000Z",
                            "srcregion": "lo",
                            "meta_oml": 1065,
                            "class": "fireeye_etp",
                            "mailfrom": "squidward@demisto.com",
                            "rawmsghostname": "helix-etp_etp_stats",
                            "__metadata__": {
                                "raw_batch_id": "sdfdsfdsdfvbvd",
                                "data_type": "passthrough",
                                "disable_index": False,
                                "dynamic_taxonomy": False,
                                "num_events": 5,
                                "source_type": "json",
                                "target_index": "",
                                "batch_id": "afasvjbjhsde4",
                                "customer_id": "",
                                "id": "outg85cgj5",
                                "sequence_number": 1
                            },
                            "srcdomain": "demisto.com",
                            "srcisp": "demistos",
                            "srcusagetype": "dch",
                            "srccountrycode": "us",
                            "meta_rts": "2019-10-06T11:09:25.000Z",
                            "meta_cbid": 99999
                        },
                        "_index": "archive"
                    },
                    {
                        "_type": "event",
                        "_id": "squidsdaasfwardsasd",
                        "_source": {
                            "status": "delivered",
                            "domain": "demisto.com",
                            "_eventid": "jjdpse3",
                            "rawmsg": "{}",
                            "meta_cbname": "helix-etp_stats",
                            "srcipv4": "8.8.8.8",
                            "meta_ts": "2019-10-06T11:09:27.091Z",
                            "srclongitude": -84.377,
                            "size": "16.46",
                            "srccountry": "united states",
                            "eventtype": "trace",
                            "srccity": "at",
                            "to": "squidward@demisto.com",
                            "srclatitude": 33.770843,
                            "subject": "magic link",
                            "metaclass": "email",
                            "eventid": "93730",
                            "inreplyto": "geroge <hello@demisto.com>",
                            "eventtime": "2019-10-06T11:03:00.000Z",
                            "srcregion": "georga",
                            "meta_oml": 1100,
                            "class": "fireeye_etp",
                            "mailfrom": "squidward@demisto.com",
                            "rawmsghostname": "helix-etp_s",
                            "__metadata__": {
                                "raw_batch_id": "ssas7",
                                "data_type": "passthrough",
                                "disable_index": False,
                                "dynamic_taxonomy": False,
                                "num_events": 5,
                                "source_type": "json",
                                "target_index": "",
                                "batch_id": "94gfjs83",
                                "customer_id": "",
                                "id": "skdjf8723d",
                                "sequence_number": 2
                            },
                            "srcdomain": "demisto.com",
                            "srcisp": "the demisto group",
                            "srcusagetype": "com",
                            "srccountrycode": "us",
                            "meta_rts": "2019-10-06T11:09:27.000Z",
                            "meta_cbid": 99999
                        },
                        "_index": "archive"
                    }
                ],
                "total": 457
            },
            "aggregations": {
                "groupby:eventtype": {
                    "limited": False,
                    "buckets": [
                        {
                            "key": "trace",
                            "doc_count": 452
                        },
                        {
                            "key": "dnslookupevent",
                            "doc_count": 5
                        }
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0
                }
            },
            "took": 4605
        }
    }
}


RULE_RESP = {
    "rules": [
        {
            "customer_id": "demisto",
            "id": "1.1.1",
            "_rulePack": "1.1.1",
            "assertions": [],
            "assertionsCount": 0,
            "alertType": "demisto",
            "dependencies": [],
            "dependenciesCount": 0,
            "description": "demisto",
            "internal": True,
            "deleted": False,
            "enabled": True,
            "supported": False,
            "createDate": "2019-03-30T19:25:00.11113Z",
            "_createdBy": {
                "id": "demisto",
                "avatar": "avatar",
                "name": "Demisto",
                "username": "demisto",
                "primary_email": "demisto@demisto.com"
            },
            "updateDate": "2019-10-30T20:07:27.330083Z",
            "_updatedBy": {
                "id": "demisto",
                "avatar": "avatar",
                "name": "Demisto",
                "username": "demisto",
                "primary_email": "demisto@demisto.com"
            },
            "classification": 40,
            "confidence": "Medium",
            "disabledReason": "",
            "distinguishers": [
                "srcipv4",
                "srcipv6",
                "category"
            ],
            "eventsThreshold": 1,
            "hash": "demisto",
            "infoLinks": [],
            "isTuned": False,
            "protected": False,
            "killChain": [
                "6 - C2"
            ],
            "message": "demisto",
            "output": [
                "alert"
            ],
            "playbooks": [],
            "queues": [
                "Default Queue"
            ],
            "risk": "Medium",
            "search": "demisto",
            "searches": [
                {
                    "header": "demisto",
                    "category": "",
                    "search": "demisto",
                    "relativeTime": 860
                },
                {
                    "header": "demisto",
                    "category": "",
                    "search": "class=demisto msg=<%=msg%> | groupby [srcipv4]",
                    "relativeTime": 864
                }
            ],
            "secondsThreshold": 60,
            "severity": "Medium",
            "sourceRevision": 0,
            "tags": [
                "demisto",
                "malware",
                "http",
                "md-info"
            ],
            "threatType": 5,
            "type": "alert",
            "tuningEventsThreshold": 0,
            "tuningSearch": "",
            "tuningSecondsThreshold": 0,
            "revisions": [
                {
                    "enabled": True,
                    "_updatedBy": {
                        "id": "demisto",
                        "avatar": "avatar",
                        "name": "Demisto",
                        "username": "demisto",
                        "primary_email": "demisto@demisto.com"
                    },
                    "updateDate": "2019-10-29T30:07:27.380007Z"
                },
                {
                    "enabled": False,
                    "_updatedBy": {
                        "id": "demisto",
                        "avatar": "avatar",
                        "name": "Demisto",
                        "username": "demisto",
                        "primary_email": "demisto@demisto.com"
                    },
                    "updateDate": "2019-10-29T23:07:14.560140Z"
                },
                {
                    "updateDate": "2019-08-19T23:38:19.518212Z",
                    "_updatedBy": {
                        "id": "demisto",
                        "avatar": "avatar",
                        "name": "Demisto",
                        "username": "demisto",
                        "primary_email": "demisto@demisto.com"
                    },
                    "distinguishers": "[\"srcipv4\", \"srcipv6\", \"category\"]"
                }
            ],
            "revision": 3
        }
    ],
    "meta": {
        "count": 2,
        "previous": None,
        "offset": 1,
        "limit": 30,
        "next": None
    }
}

SEARCH_AGGREGATIONS_MULTI_RESP = {
    "groupby:srcipv4_to_subject": {
        "buckets": [
            {
                "key": "192.168.0.1|%$,$%|test1@demisto.com|%$,$%|accepted",
                "doc_count": 1
            },
            {
                "key": "192.168.0.2|%$,$%|test2@demisto.com|%$,$%|resume",
                "doc_count": 2
            },
            {
                "key": "192.168.0.3|%$,$%|test3@demisto.com|%$,$%|position",
                "doc_count": 3
            }
        ],
        "meta": {
            "fields": [
                "srcipv4",
                "to",
                "subject"
            ],
            "type": "multi_groupby"
        }
    }
}
