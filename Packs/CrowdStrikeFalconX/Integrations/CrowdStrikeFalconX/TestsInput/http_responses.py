SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "powered_by": "falconx-api",
        "query_time": 0.163158146,
        "quota": {
            "in_progress": 3,
            "total": 100,
            "used": 36
        },
        "trace_id": "trace_id"
    },
    "resources": [
        {
            "cid": "cid",
            "created_timestamp": "2020-05-12T15:34:11Z",
            "id": "id",
            "origin": "apigateway",
            "sandbox": [
                {
                    "environment_id": 160,
                    "sha256": "sha256"
                }
            ],
            "state": "created"
        }
    ]
}

SEND_URL_TO_SANDBOX_ANALYSIS_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "powered_by": "falconx-api",
        "query_time": 0.12387683,
        "quota": {
            "in_progress": 5,
            "total": 100,
            "used": 44
        },
        "trace_id": "trace_id"
    },
    "resources": [
        {
            "cid": "cid",
            "created_timestamp": "2020-05-12T16:40:52Z",
            "id": "id",
            "origin": "apigateway",
            "sandbox": [
                {
                    "environment_id": 160,
                    "url": "https://www.google.com"
                }
            ],
            "state": "created"
        }
    ]
}

GET_FULL_REPORT_HTTP_RESPONSE_EMPTY = {
    "errors": [],
    "meta": {
        "powered_by": "falconx-api",
        "query_time": 0.006237549,
        "quota": {
            "in_progress": 2,
            "total": 100,
            "used": 47
        },
        "trace_id": "trace_id"
    },
    "resources": []
}

GET_FULL_REPORT_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "powered_by": "falconx-api",
        "query_time": 0.006237549,
        "quota": {
            "in_progress": 2,
            "total": 100,
            "used": 47
        },
        "trace_id": "trace_id"
    },
    "resources": [
        {
            "cid": "cid",
            "created_timestamp": "2020-03-16T17:04:48Z",
            "id": "id",
            "ioc_report_broad_csv_artifact_id": "ioc_report_broad_csv_artifact_id",
            "ioc_report_broad_json_artifact_id": "ioc_report_broad_json_artifact_id",
            "ioc_report_broad_maec_artifact_id": "ioc_report_broad_maec_artifact_id",
            "ioc_report_broad_stix_artifact_id": "ioc_report_broad_stix_artifact_id",
            "ioc_report_strict_csv_artifact_id": "ioc_report_strict_csv_artifact_id",
            "ioc_report_strict_json_artifact_id": "ioc_report_strict_json_artifact_id",
            "ioc_report_strict_maec_artifact_id": "ioc_report_strict_maec_artifact_id",
            "ioc_report_strict_stix_artifact_id": "ioc_report_strict_stix_artifact_id",
            "malquery": [
                {
                    "input": "input",
                    "type": "url",
                    "verdict": "whitelisted"
                },
                {
                    "input": "input",
                    "type": "url",
                    "verdict": "whitelisted"
                },
                {
                    "input": "input",
                    "type": "url",
                    "verdict": "whitelisted"
                },
                {
                    "input": "input",
                    "type": "url",
                    "verdict": "whitelisted"
                }
            ],
            "origin": "apigateway",
            "sandbox": [
                {
                    "architecture": "WINDOWS",
                    "classification": [
                        "91.6% (.URL) Windows URL shortcut",
                        "8.3% (.INI) Generic INI configuration"
                    ],
                    "contacted_hosts": [
                        {
                            "address": "111.27.12.67",
                            "associated_runtime": [
                                {
                                    "name": "name.exe",
                                    "pid": 6428
                                },
                                {
                                    "name": "name.exe",
                                    "pid": 9372
                                }
                            ],
                            "country": "United States",
                            "port": 443,
                            "protocol": "TCP"
                        },
                        {
                            "address": "111.27.12.67",
                            "associated_runtime": [
                                {
                                    "name": "name.exe",
                                    "pid": 6428
                                },
                                {
                                    "name": "name.exe",
                                    "pid": 9372
                                }
                            ],
                            "country": "United States",
                            "port": 80,
                            "protocol": "TCP"
                        },
                        {
                            "address": "111.27.12.67",
                            "associated_runtime": [
                                {
                                    "name": "name.exe",
                                    "pid": 6428
                                }
                            ],
                            "country": "United States",
                            "port": 443,
                            "protocol": "TCP"
                        },
                        {
                            "address": "111.27.12.67",
                            "associated_runtime": [
                                {
                                    "name": "name.exe",
                                    "pid": 6428
                                }
                            ],
                            "country": "United States",
                            "port": 443,
                            "protocol": "TCP"
                        },
                        {
                            "address": "111.27.12.67",
                            "associated_runtime": [
                                {
                                    "name": "name.exe",
                                    "pid": 6428
                                }
                            ],
                            "country": "United States",
                            "port": 443,
                            "protocol": "TCP"
                        },
                        {
                            "address": "111.27.12.67",
                            "associated_runtime": [
                                {
                                    "name": "name.exe",
                                    "pid": 6428
                                }
                            ],
                            "country": "United States",
                            "port": 443,
                            "protocol": "TCP"
                        },
                        {
                            "address": "111.27.12.67",
                            "associated_runtime": [
                                {
                                    "name": "name.exe",
                                    "pid": 6428
                                }
                            ],
                            "country": "United States",
                            "port": 443,
                            "protocol": "TCP"
                        }
                    ],
                    "dns_requests": [
                        {
                            "address": "111.111.1.1",
                            "country": "United States",
                            "domain": "googleads.g.doubleclick.net",
                            "registrar_creation_timestamp": "1996-01-16T00:00:00+00:00",
                            "registrar_name": "registrar_name",
                            "registrar_organization": "registrar_organization"
                        },
                        {
                            "address": "172.217.7.163",
                            "country": "United States",
                            "domain": "domain"
                        },
                        {
                            "address": "111.27.12.67",
                            "country": "United States",
                            "domain": "ssl.gstatic.com",
                            "registrar_creation_timestamp": "2008-02-11T00:00:00+00:00",
                            "registrar_name": "registrar_name",
                            "registrar_organization": "Google Inc."
                        },
                        {
                            "address": "172.217.14.163",
                            "country": "United States",
                            "domain": "www.gstatic.com",
                            "registrar_creation_timestamp": "2008-02-11T00:00:00+00:00",
                            "registrar_name": "registrar_name",
                            "registrar_organization": "registrar_organization"
                        }
                    ],
                    "environment_description": "Windows 10 64 bit",
                    "environment_id": 160,
                    "extracted_interesting_strings": [
                        {
                            "filename": "rundll32.exe",
                            "source": "Process Commandline",
                            "type": "Ansi",
                            "value": "value"
                        },
                        {
                            "filename": "filename",
                            "source": "PCAP Processing",
                            "type": "Ansi",
                            "value": "value"
                        },
                        {
                            "filename": "filename",
                            "source": "Image Processing",
                            "type": "Ansi",
                            "value": "value"
                        },
                        {
                            "filename": "screen_3.png",
                            "source": "Image Processing",
                            "type": "Ansi",
                            "value": "value"
                        },
                        {
                            "filename": "filename",
                            "source": "Image Processing",
                            "type": "Ansi",
                            "value": "value"
                        },
                        {
                            "filename": "filename",
                            "source": "PCAP Processing",
                            "type": "Ansi",
                            "value": "value"
                        },
                        {
                            "filename": "filename",
                            "source": "PCAP Processing",
                            "type": "Ansi",
                            "value": "value"
                        }
                    ],
                    "http_requests": [
                        {
                            "header": "header",
                            "host": "host",
                            "host_ip": "111.27.12.67",
                            "host_port": 80,
                            "method": "GET",
                            "url": "url"
                        },
                        {
                            "header": "header",
                            "host": "host",
                            "host_ip": "111.27.12.67",
                            "host_port": 80,
                            "method": "GET",
                            "url": "url"
                        },
                        {
                            "header": "header",
                            "host": "ocsp.pki.goog",
                            "host_ip": "172.217.7.163",
                            "host_port": 80,
                            "method": "GET",
                            "url": "url"
                        },
                        {
                            "header": "header",
                            "host": "ocsp.pki.goog",
                            "host_ip": "172.217.7.163",
                            "host_port": 80,
                            "method": "GET",
                            "url": "url"
                        },
                        {
                            "header": "header",
                            "host": "ocsp.pki.goog",
                            "host_ip": "172.217.7.163",
                            "host_port": 80,
                            "method": "GET",
                            "url": "url"
                        },
                        {
                            "header": "header",
                            "host": "ocsp.pki.goog",
                            "host_ip": "172.217.7.163",
                            "host_port": 80,
                            "method": "GET",
                            "url": "url"
                        },
                        {
                            "header": "header",
                            "host": "ocsp.pki.goog",
                            "host_ip": "172.217.7.163",
                            "host_port": 80,
                            "method": "GET",
                            "url": "url"
                        },
                        {
                            "header": "header",
                            "host": "ocsp.pki.goog",
                            "host_ip": "172.217.7.163",
                            "host_port": 80,
                            "method": "GET",
                            "url": "url"
                        }
                    ],
                    "incidents": [
                        {
                            "details": [
                                "Contacts 4 domains and 4 hosts"
                            ],
                            "name": "Network Behavior"
                        }
                    ],
                    "pcap_report_artifact_id": "pcap_report_artifact_id",
                    "processes": [
                        {
                            "command_line": "command_line",
                            "icon_artifact_id": "icon_artifact_id",
                            "name": "rundll32.exe",
                            "normalized_path": "normalized_path.exe",
                            "pid": 6648,
                            "process_flags": [
                                {
                                    "name": "Reduced Monitoring"
                                }
                            ],
                            "sha256": "sha256",
                            "uid": "00074182-00006648"
                        }
                    ],
                    "sample_flags": [
                        "Network Traffic"
                    ],
                    "screenshots_artifact_ids": [
                        "screenshots_artifact_ids1",
                        "screenshots_artifact_ids2",
                        "screenshots_artifact_ids3",
                        "screenshots_artifact_ids4"
                    ],
                    "sha256": "sha256",
                    "signatures": [
                        {
                            "category": "General",
                            "description": "description",
                            "identifier": "network-0",
                            "name": "Contacts domains",
                            "origin": "Network Traffic",
                            "relevance": 1,
                            "threat_level_human": "informative",
                            "type": 7
                        },
                        {
                            "category": "General",
                            "description": "description",
                            "identifier": "network-1",
                            "name": "Contacts server",
                            "origin": "Network Traffic",
                            "relevance": 1,
                            "threat_level_human": "informative",
                            "type": 7
                        },
                        {
                            "category": "Network Related",
                            "description": "description",
                            "identifier": "string-3",
                            "name": "Found potential URL in binary/memory",
                            "origin": "String",
                            "relevance": 10,
                            "threat_level_human": "informative",
                            "type": 2
                        },
                        {
                            "category": "External Systems",
                            "description": "description",
                            "identifier": "suricata-0",
                            "name": "Detected Suricata Alert",
                            "origin": "Suricata Alerts",
                            "relevance": 10,
                            "threat_level_human": "informative",
                            "type": 18
                        },
                        {
                            "category": "Ransomware/Banking",
                            "description": "description",
                            "identifier": "string-12",
                            "name": "Detected text artifact in screenshot that indicate file could be ransomware",
                            "origin": "String",
                            "relevance": 10,
                            "threat_level": 1,
                            "threat_level_human": "suspicious",
                            "type": 2
                        },
                        {
                            "category": "Network Related",
                            "description": "description",
                            "identifier": "network-23",
                            "name": "Sends traffic on typical HTTP outbound port, but without HTTP header",
                            "origin": "Network Traffic",
                            "relevance": 5,
                            "threat_level": 1,
                            "threat_level_human": "suspicious",
                            "type": 7
                        }
                    ],
                    "submission_type": "page_url",
                    "submit_url": "hxxps://www.google.com",
                    "suricata_alerts": [
                        {
                            "category": "Unknown Traffic",
                            "description": "ET JA3 Hash - Possible Malware - Banking Phish",
                            "destination_ip": "destination_ip",
                            "destination_port": 443,
                            "protocol": "TCP",
                            "sid": "sid"
                        },
                        {
                            "category": "Unknown Traffic",
                            "description": "ET JA3 Hash - Possible Malware - Banking Phish",
                            "destination_ip": "destination_ip",
                            "destination_port": 443,
                            "protocol": "TCP",
                            "sid": "sid"
                        },
                        {
                            "category": "Unknown Traffic",
                            "description": "ET JA3 Hash - Possible Malware - Banking Phish",
                            "destination_ip": "destination_ip",
                            "destination_port": 443,
                            "protocol": "TCP",
                            "sid": "sid"
                        },
                        {
                            "category": "Unknown Traffic",
                            "description": "ET JA3 Hash - Possible Malware - Banking Phish",
                            "destination_ip": "172.217.9.206",
                            "destination_port": 443,
                            "protocol": "TCP",
                            "sid": "sid"
                        }
                    ],
                    "threat_score": 13,
                    "verdict": "no specific threat",
                    "windows_version_bitness": 64,
                    "windows_version_edition": "Professional",
                    "windows_version_name": "Windows 10",
                    "windows_version_version": "10.0 (build 16299)"
                }
            ],
            "verdict": "no specific threat"
        }
    ]
}

GET_REPORT_SUMMARY_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "powered_by": "falconx-api",
        "query_time": 0.008725752,
        "quota": {
            "in_progress": 2,
            "total": 100,
            "used": 47
        },
        "trace_id": "trace_id"
    },
    "resources": [
        {
            "cid": "cid",
            "created_timestamp": "2020-03-16T17:04:48Z",
            "id": "id",
            "ioc_report_broad_csv_artifact_id": "ioc_report_broad_csv_artifact_id",
            "ioc_report_broad_json_artifact_id": "ioc_report_broad_json_artifact_id",
            "ioc_report_broad_maec_artifact_id": "ioc_report_broad_maec_artifact_id",
            "ioc_report_broad_stix_artifact_id": "ioc_report_broad_stix_artifact_id",
            "ioc_report_strict_csv_artifact_id": "ioc_report_strict_csv_artifact_id",
            "ioc_report_strict_json_artifact_id": "ioc_report_strict_json_artifact_id",
            "ioc_report_strict_maec_artifact_id": "ioc_report_strict_maec_artifact_id",
            "ioc_report_strict_stix_artifact_id": "ioc_report_strict_stix_artifact_id",
            "origin": "apigateway",
            "sandbox": [
                {
                    "environment_description": "Windows 10 64 bit",
                    "environment_id": 160,
                    "incidents": [
                        {
                            "details": [
                                "Contacts 4 domains and 4 hosts"
                            ],
                            "name": "Network Behavior"
                        }
                    ],
                    "sample_flags": [
                        "Network Traffic"
                    ],
                    "sha256": "sha256",
                    "submission_type": "page_url",
                    "submit_url": "hxxps://www.google.com",
                    "threat_score": 13,
                    "verdict": "no specific threat"
                }
            ],
            "verdict": "no specific threat"
        }
    ]
}

CHECK_QUOTA_STATUS_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "powered_by": "falconx-api",
        "query_time": 0.008237956,
        "quota": {
            "in_progress": 2,
            "total": 100,
            "used": 47
        },
        "trace_id": "trace_id"
    },
    "resources": None
}

FIND_SANDBOX_REPORTS_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "pagination": {
            "limit": 10,
            "offset": 0,
            "total": 69
        },
        "powered_by": "falconx-api",
        "query_time": 0.008271345,
        "quota": {
            "in_progress": 2,
            "total": 100,
            "used": 47
        },
        "trace_id": "trace_id"
    },
    "resources": [
        "resources1",
        "resources2",
        "resources3",
        "resources4"
    ]
}

FIND_SUBMISSION_ID_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "pagination": {
            "limit": 10,
            "offset": 0,
            "total": 72
        },
        "powered_by": "falconx-api",
        "query_time": 0.008812114,
        "quota": {
            "in_progress": 2,
            "total": 100,
            "used": 47
        },
        "trace_id": "trace_id"
    },
    "resources": [
        "resources1",
        "resources2",
        "resources3",
        "resources4"
    ]
}

GET_ANALYSIS_STATUS_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "powered_by": "falconx-api",
        "query_time": 0.004325809,
        "quota": {
            "in_progress": 2,
            "total": 100,
            "used": 47
        },
        "trace_id": "trace_id"
    },
    "resources": [
        {
            "cid": "cid",
            "created_timestamp": "2020-03-16T17:04:48Z",
            "id": "id",
            "origin": "apigateway",
            "sandbox": [
                {
                    "environment_id": 160,
                    "url": "hxxps://www.google.com"
                }
            ],
            "state": "success"
        }
    ]
}

MULTI_ERRORS_HTTP_RESPONSE = {
    "errors": [
        {
            "code": 403,
            "message": "access denied, authorization failed"
        },
        {
            "code": 401,
            "message": "test error #1"
        },
        {
            "code": 402,
            "message": "test error #2"
        }
    ],
    "meta": {
        "powered_by": "crowdstrike-api-gateway",
        "query_time": 0.000654734,
        "trace_id": "39f1573c-7a51-4b1a-abaa-92d29f704afd"
    }
}

NO_ERRORS_HTTP_RESPONSE = {
    "errors": [],
    "meta": {
        "powered_by": "crowdstrike-api-gateway",
        "query_time": 0.000654734,
        "trace_id": "39f1573c-7a51-4b1a-abaa-92d29f704afd"
    }
}
