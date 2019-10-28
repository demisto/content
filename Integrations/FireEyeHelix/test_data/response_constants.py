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
    "id": 23232323,
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
