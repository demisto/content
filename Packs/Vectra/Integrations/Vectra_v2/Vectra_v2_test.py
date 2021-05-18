from Vectra_v2 import *

GET_DETECTIONS_RAW_RES = {
    "count": 2,
    "next": "demisto.com/api/v2.1/detections?page=2",
    "previous": None,
    "results": [
        {
            "assigned_date": None,
            "assigned_to": None,
            "c_score": 60,
            "category": "COMMAND \u0026 CONTROL",
            "certainty": 60,
            "custom_detection": None,
            "description": None,
            "detection": "Suspicious HTTP",
            "detection_category": "COMMAND \u0026 CONTROL",
            "detection_type": "Suspicious HTTP",
            "detection_url": "demisto.com/api/v2/detections/81",
            "first_timestamp": "2019-10-11T06:39:48Z",
            "grouped_details": [
                {
                    "bytes_received": 534,
                    "bytes_sent": 354,
                    "dst_ips": [
                        "0.0.0.0"
                    ],
                    "events": [
                        {
                            "count": 1,
                            "description": "",
                            "event_type": "bot_http",
                            "host": "data.torntv.net",
                            "http_method": "GET",
                            "referrer": "",
                            "reply_cache_control": "private",
                            "url": "/country.asp?st=im\u0026uid=235601974\u0026tuid=3101429\u0026sref=SMD_18-3_0_ie_",
                            "user_agent": ""
                        }
                    ],
                    "first_timestamp": "2019-10-11T06:39:48Z",
                    "grouping_field": "target_domains",
                    "last_timestamp": "2019-10-11T06:59:43Z",
                    "target_domains": [
                        "data.torntv.net"
                    ]
                }
            ],
            "groups": [],
            "id": 81,
            "is_custom_model": False,
            "is_marked_custom": False,
            "is_targeting_key_asset": False,
            "last_timestamp": "2019-10-11T06:59:43Z",
            "note": None,
            "note_modified_by": None,
            "note_modified_timestamp": None,
            "sensor": "dOEkU9ER",
            "sensor_name": "api-demo",
            "src_account": None,
            "src_host": {
                "certainty": 0,
                "groups": [],
                "id": 48,
                "ip": "0.0.0.0",
                "is_key_asset": True,
                "name": "morpheus",
                "threat": 0,
                "url": "demisto.com/api/v2.1/hosts/48"
            },
            "src_ip": "0.0.0.0",
            "state": "inactive",
            "summary": {
                "bad_user_agent": 0,
                "beaconing": 0,
                "bytes_received": 534,
                "bytes_sent": 354,
                "suspicious_header_construction": 1
            },
            "t_score": 40,
            "tags": [],
            "targets_key_asset": False,
            "threat": 40,
            "triage_rule_id": None,
            "url": "demisto.com/api/v2/detections/81"
        },
        {
            "assigned_date": None,
            "assigned_to": None,
            "c_score": 76,
            "category": "BOTNET ACTIVITY",
            "certainty": 76,
            "custom_detection": None,
            "description": None,
            "detection": "Outbound DoS",
            "detection_category": "BOTNET ACTIVITY",
            "detection_type": "Outbound DoS",
            "detection_url": "demisto.com/api/v2/detections/80",
            "first_timestamp": "2019-10-10T13:33:27Z",
            "grouped_details": [
                {
                    "account_detection": None,
                    "account_uid": None,
                    "accounts": [],
                    "bytes_received": 1000040,
                    "bytes_sent": 1000040,
                    "dos_type": "syn_flood",
                    "dst_geo": None,
                    "dst_geo_lat": None,
                    "dst_geo_lon": None,
                    "dst_ips": [
                        "0.0.0.0"
                    ],
                    "dst_ports": [],
                    "first_timestamp": "2019-10-10T13:33:27Z",
                    "grouping_field": "last_timestamp",
                    "host_detection": 80,
                    "is_account_detail": False,
                    "is_host_detail": True,
                    "last_timestamp": "2019-10-10T13:45:08Z",
                    "num_sessions": 25001,
                    "protocol": "tcp",
                    "src_ip": "0.0.0.0",
                    "target_domains": []
                }
            ],
            "groups": [],
            "id": 80,
            "is_custom_model": False,
            "is_marked_custom": False,
            "is_targeting_key_asset": False,
            "last_timestamp": "2019-10-10T13:45:08Z",
            "note": None,
            "note_modified_by": None,
            "note_modified_timestamp": None,
            "sensor": "dOEkU9ER",
            "sensor_name": "api-demo",
            "src_account": None,
            "src_host": {
                "certainty": 0,
                "groups": [],
                "id": 140,
                "ip": "0.0.0.0",
                "is_key_asset": False,
                "name": "desktop06",
                "threat": 0,
                "url": "demisto.com/api/v2.1/hosts/140"
            },
            "src_ip": "0.0.0.0",
            "state": "inactive",
            "summary": {
                "bytes_received": 1000040,
                "bytes_sent": 1000040,
                "dos_types": [
                    "syn_flood"
                ],
                "dst_ips": [
                    "0.0.0.0"
                ],
                "num_sessions": 25001
            },
            "t_score": 19,
            "tags": [],
            "targets_key_asset": False,
            "threat": 19,
            "triage_rule_id": None,
            "url": "demisto.com/api/v2/detections/80"
        }
    ]
}

GET_HOSTS_RAW_RES = {
    "count": 2,
    "next": None,
    "previous": None,
    "results": [
        {
            "active_traffic": False,
            "assigned_date": None,
            "assigned_to": None,
            "c_score": 0,
            "certainty": 0,
            "detection_ids": [
                "39",
                "81"
            ],
            "detection_set": [
                "demisto.com/api/v2/detections/39",
                "demisto.com/api/v2/detections/81"
            ],
            "groups": [],
            "has_active_traffic": False,
            "has_custom_model": False,
            "host_artifact_set": [
                {
                    "siem": False,
                    "source": None,
                    "type": "kerberos",
                    "value": "morpheus"
                }
            ],
            "host_luid": "duGUtBa.",
            "host_session_luids": [
                "bwy.QlWP",
                "c-4.QlWP",
                "dCK.QlWP"
            ],
            "host_url": "demisto.com/api/v2/hosts/48",
            "id": 48,
            "ip": "0.0.0.0",
            "is_key_asset": True,
            "is_targeting_key_asset": False,
            "key_asset": True,
            "last_detection_timestamp": "2019-10-11T06:59:43Z",
            "last_modified": "2019-10-03T05:30:06Z",
            "last_source": "0.0.0.0",
            "name": "morpheus",
            "note": None,
            "note_modified_by": None,
            "note_modified_timestamp": None,
            "owner_name": None,
            "previous_ips": [],
            "privilege_category": None,
            "privilege_level": None,
            "sensor": None,
            "sensor_name": None,
            "severity": None,
            "state": "inactive",
            "t_score": 0,
            "tags": [],
            "targets_key_asset": False,
            "threat": 0,
            "url": "demisto.com"
        },
        {
            "active_traffic": False,
            "assigned_date": None,
            "assigned_to": None,
            "c_score": 34,
            "certainty": 34,
            "detection_ids": [
                "41",
                "54",
                "74",
                "79"
            ],
            "detection_set": [
                "demisto.com/api/v2/detections/41",
                "demisto.com/api/v2/detections/54",
                "demisto.com/api/v2/detections/74",
                "demisto.com/api/v2/detections/79"
            ],
            "groups": [],
            "has_active_traffic": False,
            "has_custom_model": False,
            "host_artifact_set": [
                {
                    "siem": False,
                    "source": None,
                    "type": "kerberos",
                    "value": "jacobb"
                }
            ],
            "host_luid": "duqUtBaD",
            "host_session_luids": [
                "c-W.D4-N",
                "c9G.D4-N",
                "cme.D4-N",
                "d2O.D4-N"
            ],
            "host_url": "demisto.com/api/v2/hosts/80",
            "id": 80,
            "ip": "0.0.0.0",
            "is_key_asset": True,
            "is_targeting_key_asset": False,
            "key_asset": True,
            "last_detection_timestamp": "2019-10-10T07:23:49Z",
            "last_modified": "2019-10-03T13:53:06Z",
            "last_source": "0.0.0.0",
            "name": "jacobb",
            "note": None,
            "note_modified_by": None,
            "note_modified_timestamp": None,
            "owner_name": None,
            "previous_ips": [],
            "privilege_category": None,
            "privilege_level": None,
            "sensor": None,
            "sensor_name": None,
            "severity": "low",
            "state": "active",
            "t_score": 6,
            "tags": [],
            "targets_key_asset": False,
            "threat": 6,
            "url": "demisto.comapi/v2/hosts/80"
        }
    ]
}

GET_THREATFEED_RAW_RESPONSE = {
    "meta": {
        "count": 1
    },
    "threatFeeds": [
        {
            "_rev": "1-b856f9dfde82dd8a206f2542a82076fa",
            "category": "exfil",
            "certainty": "Medium",
            "defaults": {
                "category": "exfil",
                "certainty": "Medium",
                "duration": 14,
                "indicatorType": "Exfiltration"
            },
            "duration": 14,
            "id": "50f897f3c9bdc606472e8d72348c3263",
            "indicatorType": "Exfiltration",
            "lastUpdated": "2019-10-04T17:12:00.978052+00:00",
            "lastUpdatedBy": "vadmin",
            "name": "Suspicious Domains",
            "type": "STIX",
            "uploadDate": "2019-10-04T17:12:00.978052+00:00",
            "uploadResults": None,
            "version": "5.0-143-gb19b326"
        }
    ]
}

SEARCH_HOSTS_RAW_RESPONSE = {
    "count": 2,
    "next": None,
    "previous": None,
    "results": [
        {
            "_doc_modified_ts": "2019-10-27T06:00:05.215109",
            "active_traffic": False,
            "assigned_date": None,
            "assigned_to": None,
            "campaign_summaries": [],
            "certainty": 38,
            "detection_summaries": [
                {
                    "assigned_date": None,
                    "assigned_to": None,
                    "certainty": 10,
                    "detection_category": "EXFILTRATION",
                    "detection_id": 60,
                    "detection_type": "Smash and Grab",
                    "is_targeting_key_asset": False,
                    "is_triaged": False,
                    "state": "active",
                    "summary": {
                        "bytes_sent": 73616289,
                        "dst_ips": [
                            "0.0.0.0"
                        ],
                        "subnet": None
                    },
                    "tags": [],
                    "threat": 69
                },
                {
                    "assigned_date": None,
                    "assigned_to": None,
                    "certainty": 95,
                    "detection_category": "LATERAL MOVEMENT",
                    "detection_id": 56,
                    "detection_type": "Privilege Anomaly: Unusual Account on Host",
                    "is_targeting_key_asset": False,
                    "is_triaged": False,
                    "state": "active",
                    "summary": {
                        "services_accessed": [
                            {
                                "id": None,
                                "name": "cifs/fs-srv-99.corp.example.com",
                                "privilege_category": "High",
                                "privilege_level": 8
                            }
                        ],
                        "src_accounts": [
                            {
                                "id": 26,
                                "name": "cj@corp.example.com",
                                "privilege_category": "High",
                                "privilege_level": 8
                            }
                        ],
                        "src_hosts": [
                            {
                                "id": 103,
                                "name": "winfs06r3u17",
                                "privilege_category": "Low",
                                "privilege_level": 1
                            }
                        ]
                    },
                    "tags": [],
                    "threat": 55
                },
                {
                    "assigned_date": None,
                    "assigned_to": None,
                    "certainty": 10,
                    "detection_category": "COMMAND \u0026 CONTROL",
                    "detection_id": 53,
                    "detection_type": "Hidden HTTPS Tunnel",
                    "is_targeting_key_asset": False,
                    "is_triaged": False,
                    "state": "inactive",
                    "summary": {
                        "bytes_received": 1905395,
                        "bytes_sent": 1272827,
                        "dst_ips": [
                            "1.1.1.1"
                        ],
                        "num_sessions": 2922
                    },
                    "tags": [],
                    "threat": 10
                }
            ],
            "groups": [],
            "has_active_traffic": False,
            "has_custom_model": False,
            "has_shell_knocker_learnings": False,
            "host_artifact_set": [
                {
                    "siem": False,
                    "source": None,
                    "type": "kerberos",
                    "value": "winfs06r3u17"
                }
            ],
            "host_luid": "dwGUtBaK",
            "host_session_luids": [
                "cB8.1f0j",
                "c80.1f0j"
            ],
            "id": 103,
            "ip": "0.0.0.0",
            "is_key_asset": False,
            "is_targeting_key_asset": False,
            "key_asset": False,
            "last_detection_timestamp": "2019-10-04T19:24:04Z",
            "last_modified": "2019-10-04T12:40:38Z",
            "last_seen": "2019-10-04T18:56:40Z",
            "last_source": "0.0.0.0",
            "name": "winfs06r3u17",
            "note": None,
            "note_modified_by": None,
            "note_modified_timestamp": None,
            "owner_name": None,
            "previous_ips": [],
            "privilege_category": None,
            "privilege_level": None,
            "sensor": None,
            "sensor_name": None,
            "severity": "low",
            "shell_knocker": [],
            "state": "active",
            "suspicious_admin_learnings": {
                "host_manages": [],
                "managers_of_host": []
            },
            "tags": [],
            "targets_key_asset": False,
            "threat": 38
        },
        {
            "_doc_modified_ts": "2019-10-27T09:00:02.164610",
            "active_traffic": False,
            "assigned_date": None,
            "assigned_to": None,
            "campaign_summaries": [],
            "certainty": 47,
            "detection_summaries": [
                {
                    "assigned_date": None,
                    "assigned_to": None,
                    "certainty": 95,
                    "detection_category": "EXFILTRATION",
                    "detection_id": 12,
                    "detection_type": "Data Smuggler",
                    "is_targeting_key_asset": False,
                    "is_triaged": False,
                    "state": "active",
                    "summary": {
                        "bytes_sent": 251817582,
                        "dst_ips": [
                            "s3-1-w.amazonaws.com"
                        ],
                        "dst_ports": [
                            443
                        ],
                        "protocols": [
                            "tcp"
                        ]
                    },
                    "tags": [],
                    "threat": 74
                },
                {
                    "assigned_date": None,
                    "assigned_to": None,
                    "certainty": 10,
                    "detection_category": "RECONNAISSANCE",
                    "detection_id": 11,
                    "detection_type": "File Share Enumeration",
                    "is_targeting_key_asset": False,
                    "is_triaged": False,
                    "state": "active",
                    "summary": {
                        "common_shares": [],
                        "dst_ips": [
                            "0.0.0.0"
                        ],
                        "num_accounts": 1,
                        "shares": [
                            "nmap-share-test",
                            "ADMIN$",
                            "IPC$",
                            "INFO$",
                            "DESKTOP",
                            "GROUPS$",
                            "GROUPS",
                            "HOME",
                            "DATA",
                            "HD",
                            "A$",
                            "E$",
                            "C$",
                            "ADMIN",
                            "G$",
                            "DESKTOP$",
                            "HOME$",
                            "DOCS",
                            "I$",
                            "A",
                            "B$",
                            "C",
                            "B",
                            "E",
                            "D",
                            "G",
                            "F",
                            "I",
                            "H",
                            "BACKUP$",
                            "DOCS$",
                            "FILES$",
                            "INFO",
                            "IPC",
                            "DATA$",
                            "D$",
                            "HD$",
                            "F$",
                            "BACKUP",
                            "FILES",
                            "H$"
                        ]
                    },
                    "tags": [],
                    "threat": 70
                },
                {
                    "assigned_date": None,
                    "assigned_to": None,
                    "certainty": 95,
                    "detection_category": "LATERAL MOVEMENT",
                    "detection_id": 9,
                    "detection_type": "Privilege Anomaly: Unusual Service",
                    "is_targeting_key_asset": False,
                    "is_triaged": False,
                    "state": "active",
                    "summary": {
                        "services_accessed": [
                            {
                                "id": None,
                                "name": "MSSQLSvc/sqlsrv1.corp.example.com",
                                "privilege_category": None,
                                "privilege_level": None
                            }
                        ],
                        "src_accounts": [
                            {
                                "id": 1,
                                "name": "cindy@corp.example.com",
                                "privilege_category": None,
                                "privilege_level": None
                            }
                        ],
                        "src_hosts": [
                            {
                                "id": 31,
                                "name": "Cindy-Mac",
                                "privilege_category": None,
                                "privilege_level": None
                            }
                        ]
                    },
                    "tags": [],
                    "threat": 75
                }
            ],
            "groups": [],
            "has_active_traffic": False,
            "has_custom_model": False,
            "has_shell_knocker_learnings": False,
            "host_artifact_set": [
                {
                    "siem": False,
                    "source": None,
                    "type": "mac",
                    "value": "f4:5c:89:94:10:69",
                    "vendor": "Apple, Inc"
                },
                {
                    "siem": False,
                    "source": None,
                    "type": "dhcp",
                    "value": "Cindy-Mac"
                }
            ],
            "host_luid": "du4UtBZw",
            "host_session_luids": [
                "bvi.5tXk"
            ],
            "id": 31,
            "ip": "0.0.0.0",
            "is_key_asset": False,
            "is_targeting_key_asset": False,
            "key_asset": False,
            "last_detection_timestamp": "2019-10-03T02:11:12Z",
            "last_modified": "2019-10-03T02:25:06Z",
            "last_seen": "2019-10-03T02:21:54Z",
            "last_source": "0.0.0.0",
            "name": "Cindy-Mac",
            "note": None,
            "note_modified_by": None,
            "note_modified_timestamp": None,
            "owner_name": None,
            "previous_ips": [],
            "privilege_category": None,
            "privilege_level": None,
            "sensor": None,
            "sensor_name": None,
            "severity": "low",
            "shell_knocker": [],
            "state": "active",
            "suspicious_admin_learnings": {
                "host_manages": [],
                "managers_of_host": []
            },
            "tags": [],
            "targets_key_asset": False,
            "threat": 31
        }
    ]
}

HOST_BY_ID_RAW_RES = {
    "count": 1,
    "next": None,
    "previous": None,
    "results": [
        {
            "_doc_modified_ts": "2019-10-27T09:00:03.220726",
            "active_traffic": False,
            "assigned_date": None,
            "assigned_to": None,
            "campaign_summaries": [],
            "certainty": 56,
            "detection_summaries": [
                {
                    "assigned_date": None,
                    "assigned_to": None,
                    "certainty": 95,
                    "detection_category": "LATERAL MOVEMENT",
                    "detection_id": 18,
                    "detection_type": "Ransomware File Activity",
                    "is_targeting_key_asset": False,
                    "is_triaged": False,
                    "state": "active",
                    "summary": {
                        "bytes_received": 149147729,
                        "dst_ips": [
                            "0.0.0.0"
                        ],
                        "num_files": 61,
                        "num_shares": 2,
                        "shares": [
                            "\\\\DATA\\reports",
                            "\\\\DATA\\documents"
                        ]
                    },
                    "tags": [],
                    "threat": 90
                },
                {
                    "assigned_date": None,
                    "assigned_to": None,
                    "certainty": 13,
                    "detection_category": "COMMAND \u0026 CONTROL",
                    "detection_id": 16,
                    "detection_type": "TOR Activity",
                    "is_targeting_key_asset": False,
                    "is_triaged": False,
                    "state": "inactive",
                    "summary": {
                        "bytes_received": 492040,
                        "bytes_sent": 18644,
                        "dst_ips": [
                            "0.0.0.0"
                        ],
                        "num_sessions": 0
                    },
                    "tags": [],
                    "threat": 14
                },
                {
                    "assigned_date": None,
                    "assigned_to": None,
                    "certainty": 13,
                    "detection_category": "COMMAND \u0026 CONTROL",
                    "detection_id": 1,
                    "detection_type": "TOR Activity",
                    "is_targeting_key_asset": False,
                    "is_triaged": False,
                    "state": "inactive",
                    "summary": {
                        "bytes_received": 492040,
                        "bytes_sent": 18644,
                        "dst_ips": [
                            "0.0.0.0"
                        ],
                        "num_sessions": 0
                    },
                    "tags": [],
                    "threat": 14
                }
            ],
            "groups": [],
            "has_active_traffic": False,
            "has_custom_model": False,
            "has_shell_knocker_learnings": False,
            "host_artifact_set": [
                {
                    "siem": False,
                    "source": None,
                    "type": "mac",
                    "value": "00:31:45:65:af:de",
                    "vendor": None
                },
                {
                    "siem": False,
                    "source": None,
                    "type": "dhcp",
                    "value": "DJComp"
                }
            ],
            "host_luid": "dtuUtBZl",
            "host_session_luids": [
                "bwW.e33V",
                "buC.e33V"
            ],
            "id": 4,
            "ip": "0.0.0.0",
            "is_key_asset": False,
            "is_targeting_key_asset": False,
            "key_asset": False,
            "last_detection_timestamp": "2019-10-03T04:40:40Z",
            "last_modified": "2019-10-02T22:54:06Z",
            "last_seen": "2019-10-03T04:51:53Z",
            "last_source": "0.0.0.0",
            "name": "DJComp",
            "note": None,
            "note_modified_by": None,
            "note_modified_timestamp": None,
            "owner_name": "dwilson",
            "previous_ips": [],
            "privilege_category": None,
            "privilege_level": None,
            "sensor": None,
            "sensor_name": None,
            "severity": "medium",
            "shell_knocker": [],
            "state": "active",
            "suspicious_admin_learnings": {
                "host_manages": [],
                "managers_of_host": []
            },
            "tags": [],
            "targets_key_asset": False,
            "threat": 17
        }
    ]
}

DETECTION_BY_ID_RAW_RES = {
    "count": 1,
    "next": None,
    "previous": None,
    "results": [
        {
            "_doc_modified_ts": "2019-10-27T09:21:35.837446",
            "assigned_date": None,
            "assigned_to": None,
            "campaign_summaries": [],
            "category": "BOTNET ACTIVITY",
            "certainty": 10,
            "custom_detection": None,
            "description": None,
            "detection": "Abnormal Ad Activity",
            "detection_category": "BOTNET ACTIVITY",
            "detection_type": "Abnormal Ad Activity",
            "first_timestamp": "2019-10-02T22:07:39Z",
            "grouped_details": [
                {
                    "account_detection": None,
                    "account_uid": None,
                    "accounts": [],
                    "bytes_received": None,
                    "bytes_sent": None,
                    "dst_geo": None,
                    "dst_geo_lat": None,
                    "dst_geo_lon": None,
                    "dst_ips": [],
                    "dst_ports": [],
                    "first_timestamp": "2019-10-02T22:07:39Z",
                    "host_detection": 4,
                    "is_account_detail": False,
                    "is_host_detail": True,
                    "last_timestamp": "2019-10-02T22:29:19Z",
                    "num_ad_sessions": 184,
                    "num_sessions": 2076,
                    "src_ip": "0.0.0.0",
                    "target_domains": []
                },
                {
                    "account_detection": None,
                    "account_uid": None,
                    "accounts": [],
                    "bytes_received": None,
                    "bytes_sent": None,
                    "dst_geo": None,
                    "dst_geo_lat": None,
                    "dst_geo_lon": None,
                    "dst_ips": [],
                    "dst_ports": [],
                    "first_timestamp": "2019-10-02T22:01:46Z",
                    "host_detection": 4,
                    "is_account_detail": False,
                    "is_host_detail": True,
                    "last_timestamp": "2019-10-02T22:05:19Z",
                    "num_ad_sessions": 114,
                    "num_sessions": 1924,
                    "src_ip": "0.0.0.0",
                    "target_domains": []
                }
            ],
            "groups": [],
            "id": 4,
            "is_custom_model": False,
            "is_marked_custom": False,
            "is_targeting_key_asset": False,
            "is_triaged": False,
            "last_timestamp": "2019-10-02T22:29:19Z",
            "note": None,
            "note_modified_by": None,
            "note_modified_timestamp": None,
            "sensor": "dOEkU9ER",
            "sensor_name": "api-demo",
            "src_account": None,
            "src_host": {
                "certainty": 33,
                "groups": [],
                "id": 7,
                "ip": "0.0.0.0",
                "is_key_asset": True,
                "name": "BThomas-Win7",
                "threat": 23
            },
            "src_ip": "0.0.0.0",
            "state": "inactive",
            "summary": {
                "duration": 1653,
                "num_sessions": 4000,
                "reason": "Abnormal frequency of redirects",
                "sessions_with_ad_activity": 298,
                "total_active_time": "0:27:33"
            },
            "tags": [],
            "targets_key_asset": False,
            "threat": 30,
            "triage_rule_id": None
        }
    ]
}


class Client_mock(Client):
    def __init__(self, mock, incidents=None, last_run=None):
        super().__init__('', '', False, {}, 0, 0, 0, '', state='active')
        self.incidents = incidents
        self.last_run = last_run
        self.mock = mock

    def http_request(self, method='GET', url_suffix='', params=None, data=None):
        return self.mock


def test_get_detections():
    client = Client_mock(GET_DETECTIONS_RAW_RES)
    readable_output, outputs, raw_response = get_detections_command(client, **demisto.args())
    assert outputs.get('Vectra.Detection(val.ID==obj.ID)')[0].get('ID') == 80


def test_get_hosts():
    client = Client_mock(GET_HOSTS_RAW_RES)
    readable_output, outputs, raw_response = get_hosts_command(client, **demisto.args())
    assert outputs.get('Vectra.Host(val.ID==obj.ID)')[0].get('ID') == 48


def test_get_threatfeed():
    client = Client_mock(GET_THREATFEED_RAW_RESPONSE)
    readable_output, outputs, raw_response = get_threatfeed_command(client, demisto.getArg('threatfeed_id'))
    assert outputs.get('Vectra.ThreatFeed(val.ID==obj.ID)')[0].get('ID') == '50f897f3c9bdc606472e8d72348c3263'


def test_search():
    # !vectra-search search_type=hosts query_string=`host.threat:>=20 and host.certainty:>=20`
    client = Client_mock(SEARCH_HOSTS_RAW_RESPONSE)
    readable_output, outputs, raw_response = search_command(client, search_type='hosts')
    assert outputs.get('Vectra.Host(val.ID==obj.ID)')[0].get('ID') == 31


def test_get_host_by_id():
    client = Client_mock(HOST_BY_ID_RAW_RES)
    query_string = f'host.id:{demisto.args().get("host_id")}'
    readable_output, outputs, raw_response = search_command(client, search_type='hosts', query_string=query_string)
    assert outputs.get('Vectra.Host(val.ID==obj.ID)')[0].get('ID') == 4


def test_get_detection_by_id():
    client = Client_mock(DETECTION_BY_ID_RAW_RES)
    query_string = f'detection.id:{demisto.args().get("detection_id")}'
    readable_output, outputs, raw_response = search_command(client, search_type='detections', query_string=query_string)
    assert outputs.get('Vectra.Detection(val.ID==obj.ID)')[0].get('ID') == 4
