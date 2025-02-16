import copy

valid_ip_response = {
    "ip": "71.6.135.131",  # NOSONAR
    "seen": True,
    "riot": False,
    "classification": "malicious",
    "first_seen": "2019-04-04",
    "last_seen": "2019-08-21",
    "actor": "unknown",
    "tags": ["MSSQL Bruteforcer", "MSSQL Scanner", "RDP Scanner"],
    "vpn": True,
    "vpn_service": "dummy vpn",
    "bot": True,
    "metadata": {
        "country": "China",
        "country_code": "CN",
        "city": "Kunshan",
        "organization": "CHINANET jiangsu province network",
        "asn": "AS4134",
        "tor": False,
        "os": "Windows 7/8",
        "category": "isp",
    },
    "raw_data": {
        "scan": [
            {"port": 1433, "protocol": "TCP"},
            {"port": 3389, "protocol": "TCP"},
            {"port": 65529, "protocol": "TCP"},
        ],
        "web": {
            "paths": ["/sitemap.xml", "/.well-known/security.txt", "/favicon.ico", "/robots.txt", "/"],
            "useragents": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0", ""],
        },
        "ja3": [
            {"fingerprint": "30017f6f809155387cbcf95be6e7225d", "port": 443},
            {"fingerprint": "330ed8deb9b34592442c3bb392ee0926", "port": 444},
        ],
        "hassh": [
            {"fingerprint": "30017f6f809155387cbcf95be6e7225d", "port": 443},
            {"fingerprint": "330ed8deb9b34592442c3bb392ee0926", "port": 444},
        ],
    },
}

valid_ip_response_expected = copy.deepcopy(valid_ip_response)
valid_ip_response_expected["address"] = valid_ip_response["ip"]
del valid_ip_response_expected["ip"]

# input_data, expected_output
parse_code_and_body_data = [
    ("(400, 'dummy message')", (400, "dummy message")),
    ("(500, 'dummy message2')", (500, "dummy message2")),
    ("dummy error", (0, "dummy error")),
]

# api_key, api_response, status_code, expected_output
test_module_data = [
    ("true_key", {"expiration": "2026-01-01", "message": "pong", "offering": "vip"}, 200, "ok"),
    ("dummy_key", "forbidden", 401, "Unauthenticated. Check the configured API Key."),
    ("dummy_key", "", 429, "API Rate limit hit. Try after sometime."),
    ("dummy_key", "Dummy message", 405, "Failed to execute  command.\n Error: Dummy message"),
    (
        "dummy_key",
        "Dummy message",
        505,
        "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    ),
]

ip_reputation_command_data = [
    ({"ip": "71.6.135.131"}, "positive", valid_ip_response, 200, valid_ip_response_expected),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "positive",
        {"ip": "71.6.135.131", "seen": False, "riot": False},
        200,  # NOSONAR
        {"address": "71.6.135.131", "seen": False, "riot": False},
    ),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "negative",
        "invalid ip response",
        200,  # NOSONAR
        "Invalid response from GreyNoise. Response: invalid ip response",
    ),  # NOSONAR
    ({"ip": "71.6.135.131"}, "negative", "forbidden", 401, "Unauthenticated. Check the configured API Key."),  # NOSONAR
    ({"ip": "71.6.135.131"}, "negative", {}, 429, "API Rate limit hit. Try after sometime."),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "negative",
        "Dummy message",
        405,  # NOSONAR
        "Failed to execute  command.\n Error: Dummy message",
    ),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "negative",
        {},
        505,  # NOSONAR
        "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    ),  # NOSONAR
    ({"ip": "5844.2204.2191.2471"}, "negative", {}, 200, "Invalid IP address: '5844.2204.2191.2471'"),  # NOSONAR
]

get_ip_reputation_score_data = [
    ("unknown", (2, "Suspicious")),
    ("", (0, "Unknown")),
    ("benign", (1, "Good")),
    ("malicious", (3, "Bad")),
    ("dummy", (0, "Unknown")),
]

valid_quick_response = [
    {
        "ip": "71.6.135.131",  # NOSONAR
        "noise": False,
        "code": "0x01",  # NOSONAR
        "code_message": "IP has been observed by the GreyNoise sensor network",
    }
]

valid_multiple_qc_resp = [
    {
        "ip": "71.5.135.131",  # NOSONAR
        "noise": False,
        "code": "0x00",  # NOSONAR
        "code_message": "IP has never been observed scanning the Internet",
    },
    {
        "ip": "8.8.8.8",  # NOSONAR
        "noise": False,
        "code": "0x00",  # NOSONAR
        "code_message": "IP has never been observed scanning the Internet",
    },
]
valid_quick_response_expected = copy.deepcopy(valid_quick_response)
for resp in valid_quick_response_expected:
    resp["address"] = resp["ip"]
    resp["code_value"] = resp["code_message"]
    del resp["ip"], resp["code_message"]

valid_multiple_qc_resp_expected = copy.deepcopy(valid_multiple_qc_resp)
for resp in valid_multiple_qc_resp_expected:
    resp["address"] = resp["ip"]
    resp["code_value"] = resp["code_message"]
    del resp["ip"], resp["code_message"]

# ip, test_scenario, api_response, status_code, expected_output
ip_quick_check_command_data = [
    ({"ip": "71.6.135.131"}, "positive", valid_quick_response, 200, valid_quick_response_expected),  # NOSONAR
    (
        {"ip": "71.6.135.131,8.8.8.8"},
        "positive",
        valid_multiple_qc_resp,
        200,  # NOSONAR
        valid_multiple_qc_resp_expected,
    ),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "custom",
        "invalid ip response",
        200,  # NOSONAR
        "Invalid response from GreyNoise. Response: invalid ip response",
    ),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "negative",
        "forbidden",
        401,  # NOSONAR
        "Unauthenticated. Check the configured API Key.",
    ),  # NOSONAR
    ({"ip": "71.6.135.131"}, "negative", [], 429, "API Rate limit hit. Try after sometime."),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "negative",
        "Dummy message",
        405,  # NOSONAR
        "Failed to execute  command.\n Error: Dummy message",
    ),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "negative",
        [],
        505,  # NOSONAR
        "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    ),  # NOSONAR
    ({"ip": "5844.2204.2191.2471"}, "negative", [], 200, "Invalid IP address: '5844.2204.2191.2471'"),  # NOSONAR
    ({"ip": ""}, "negative", [], 200, "Invalid IP address: ''"),  # NOSONAR
]

generate_advanced_query_data = [
    ({}, "spoofable:false"),
    ({"spoofable": "false"}, "spoofable:false"),
    ({"spoofable": "true"}, "spoofable:true"),
    (
        {"spoofable": "true", "actor": "dummy", "classification": "benign"},
        "actor:dummy classification:benign spoofable:true",
    ),
    ({"advanced_query": "spoofable:false"}, "spoofable:false"),
    ({"advanced_query": "spoofable:true"}, "spoofable:true"),
    ({"advanced_query": "spoofable:false", "spoofable": "true"}, "spoofable:false"),
    ({"advanced_query": "spoofable:false", "spoofable": "false"}, "spoofable:false"),
    ({"advanced_query": "spoofable:true", "spoofable": "true"}, "spoofable:true"),
    ({"advanced_query": "spoofable:true", "spoofable": "false"}, "spoofable:true"),
    ({"advanced_query": "dummy:value"}, "dummy:value"),
    ({"advanced_query": "dummy: value"}, "dummy:value"),
    ({"advanced_query": "dummy :value"}, "dummy:value"),
    ({"advanced_query": "dummy : value"}, "dummy:value"),
    ({"advanced_query": "classification : benign dummy: value"}, "classification:benign dummy:value"),
    ({"advanced_query": "actor:value", "actor": "value2"}, "actor:value"),
    ({"advanced_query": "actor:value", "spoofable": "value"}, "actor:value spoofable:value"),
]

valid_query_response = {
    "complete": False,
    "count": 1,
    "data": [
        {
            "ip": "71.6.135.131",  # NOSONAR
            "seen": True,
            "classification": "malicious",
            "first_seen": "2019-04-04",
            "last_seen": "2019-08-21",
            "actor": "unknown",
            "tags": ["mssql bruteforcer", "mssql scanner", "rdp scanner"],
            "vpn": True,
            "vpn_service": "dummy vpn",
            "metadata": {
                "country": "china",
                "country_code": "cn",
                "city": "kunshan",
                "organization": "chinanet jiangsu province network",
                "asn": "as4134",
                "tor": False,
                "os": "windows 7/8",
                "category": "isp",
            },
            "raw_data": {
                "scan": [
                    {"port": 1433, "protocol": "tcp"},
                    {"port": 3389, "protocol": "tcp"},
                    {"port": 65529, "protocol": "tcp"},
                ],
                "web": {
                    "paths": ["/sitemap.xml", "/.well-known/security.txt", "/favicon.ico", "/robots.txt", "/"],
                    "useragents": ["useragent0", "useragent1", "useragent2"],
                },
                "ja3": [
                    {"fingerprint": "30017f6f809155387cbcf95be6e7225d", "port": 443},
                    {"fingerprint": "330ed8deb9b34592442c3bb392ee0926", "port": 444},
                ],
                "hassh": [
                    {"fingerprint": "30017f6f809155387cbcf95be6e7225d", "port": 443},
                    {"fingerprint": "330ed8deb9b34592442c3bb392ee0926", "port": 444},
                ],
            },
        }
    ],
    "message": "ok",
    "query": "dummy_query",
    "scroll": "dummy_scroll",
}

valid_query_response_expected = copy.deepcopy(valid_query_response)
for each in valid_query_response_expected.get("data"):  # type: ignore
    each["address"] = each["ip"]
    del each["ip"]

query_command_data: list = [
    ({}, "positive", valid_query_response, 200, valid_query_response_expected),  # NOSONAR
    ({}, "negative", "dummy message", 200, "Invalid response from GreyNoise. Response: dummy message"),  # NOSONAR
    (
        {},
        "negative",
        {"message": "dummy_message"},
        200,  # NOSONAR
        "GreyNoise request failed. Reason: dummy_message",
    ),  # NOSONAR
    ({}, "negative", "forbidden", 401, "Unauthenticated. Check the configured API Key."),  # NOSONAR
    ({}, "negative", {}, 429, "API Rate limit hit. Try after sometime."),  # NOSONAR
    ({}, "negative", "Dummy message", 405, "Failed to execute  command.\n Error: Dummy message"),  # NOSONAR  # NOSONAR
    (
        {},
        "negative",
        {},
        505,  # NOSONAR
        "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    ),  # NOSONAR
]

valid_stats_response = {
    "query": "classification:benign spoofable:false",
    "count": 8225,
    "stats": {
        "classifications": [{"classification": "benign", "count": 8225}],
        "spoofable": [{"spoofable": False, "count": 8225}],
        "organizations": [{"organization": "Google LLC", "count": 2078}],
        "actors": [{"actor": "GoogleBot", "count": 2087}],
        "countries": [{"country": "United States", "count": 4994}],
        "tags": [{"tag": "Web Crawler", "count": 6654}],
        "operating_systems": [{"operating_system": "Linux 2.2-3.x", "count": 5307}],
        "categories": [{"category": "business", "count": 3946}],
        "asns": [{"asn": "AS15169", "count": 2078}],
    },
}
invalid_stats_response = {
    "query": "classification:sdcsdc spoofable:false",
    "count": 0,
    "stats": {
        "classifications": None,
        "spoofable": None,
        "organizations": None,
        "actors": None,
        "countries": None,
        "tags": None,
        "operating_systems": None,
        "categories": None,
        "asns": None,
    },
}
invalid_stats_response_expected = copy.deepcopy(invalid_stats_response)
valid_stats_response_expected = copy.deepcopy(valid_stats_response)
stats_command_data: list = [
    ({}, "positive", valid_stats_response, 200, valid_stats_response_expected),  # NOSONAR
    ({}, "negative", "dummy message", 200, "Invalid response from GreyNoise. Response: dummy message"),  # NOSONAR
    (
        {},
        "positive",
        invalid_stats_response,
        200,
        {"count": 0, "query": "classification:sdcsdc spoofable:false"},
    ),  # NOSONAR
    ({}, "negative", "forbidden", 401, "Unauthenticated. Check the configured API Key."),  # NOSONAR
    ({}, "negative", {}, 429, "API Rate limit hit. Try after sometime."),  # NOSONAR
    ({}, "negative", "Dummy message", 405, "Failed to execute  command.\n Error: Dummy message"),  # NOSONAR  # NOSONAR
    (
        {},
        "negative",
        {},
        505,  # NOSONAR
        "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    ),  # NOSONAR
]

valid_ip_context_data = {
    "ip": "71.6.135.131",  # NOSONAR
    "seen": True,
    "classification": "malicious",
    "first_seen": "2019-04-04",
    "last_seen": "2019-08-21",
    "actor": "unknown",
    "tags": ["mssql bruteforcer", "mssql scanner", "rdp scanner"],
    "vpn": True,
    "vpn_service": "dummy vpn",
    "metadata": {
        "country": "china",
        "country_code": "cn",
        "city": "kunshan",
        "organization": "chinanet jiangsu province network",
        "asn": "as4134",
        "tor": False,
        "os": "windows 7/8",
        "category": "isp",
    },
    "raw_data": {
        "scan": [
            {"port": 1433, "protocol": "tcp"},
            {"port": 3389, "protocol": "tcp"},
            {"port": 65529, "protocol": "tcp"},
        ],
        "web": {
            "paths": ["/sitemap.xml", "/.well-known/security.txt", "/favicon.ico", "/robots.txt", "/"],
            "useragents": ["useragent0", "useragent1", "useragent2"],
        },
        "ja3": [
            {"fingerprint": "30017f6f809155387cbcf95be6e7225d", "port": 443},
            {"fingerprint": "330ed8deb9b34592442c3bb392ee0926", "port": 444},
        ],
        "hassh": [
            {"fingerprint": "30017f6f809155387cbcf95be6e7225d", "port": 443},
            {"fingerprint": "330ed8deb9b34592442c3bb392ee0926", "port": 444},
        ],
    },
}

valid_ip_context_data_response = [
    {
        "MetaData": [
            "Country: china",
            "Country Code: cn",
            "City: kunshan",
            "Organization: chinanet jiangsu province network",
            "ASN: as4134",
            "Tor: False",
            "OS: windows 7/8",
            "Category: isp",
        ],
        "VPN": True,
        "VPN Service": "dummy vpn",
        "Tor": False,
        "IP": "[71.6.135.131](https://viz.greynoise.io/ip/71.6.135.131)",  # NOSONAR
        "Seen": True,
        "Classification": "malicious",
        "First Seen": "2019-04-04",
        "Last Seen": "2019-08-21",
        "Actor": "unknown",
        "Tags": ["mssql bruteforcer", "mssql scanner", "rdp scanner"],
    }
]

get_ip_context_data_data = [([valid_ip_context_data], valid_ip_context_data_response)]

valid_riot_response = {
    "output": {
        "ip": "8.8.8.8",
        "riot": True,
        "category": "public_dns",
        "name": "Google Public DNS",
        "description": "Google's global domain name system (DNS) resolution service.",
        "explanation": "Public DNS services are used as alternatives to ISP's name servers. "
                       "You may see devices on your network communicating with Google Public DNS over port "
                       "53/TCP or 53/UDP to resolve DNS lookups.",
        "last_updated": "2021-04-12T09:55:37Z",
        "reference": "https://developers.google.com/speed/public-dns/docs/isp#alternative",
    },
    "readable": "### IP: 8.8.8.8 found with RIOT Reputation: Unknown\nBelongs to Common Business Service: "
                "Google Public DNS\n### GreyNoise RIOT IP Lookup\n|IP|Category|Name|Trust Level|Description|Last Updated|\n"
                "|---|---|---|---|---|---|\n| [8.8.8.8](https://viz.greynoise.io/ip/8.8.8.8) | public_dns | Google Public DNS "
                "|  | Google's global domain name system (DNS) resolution service. | 2021-04-12T09:55:37Z |\n"
}

valid_riot_response_2 = {"output": {"ip": "114.119.130.178", "riot": False},
                         "readable": "### IP: 114.119.130.178 Not Associated with Common Business Service"
                                     "\n### GreyNoise RIOT IP Lookup\n|IP|RIOT|\n|---|---|\n| 114.119.130.178 | false |\n"}
invalid_riot_response = {
    "output": {"message": "IP provided is not a routable IPv4 address"},
    "error_message": "Invalid IP address: '{}'",
}
riot_command_response_data = [
    ("positive", 200, {"ip": "8.8.8.8"}, valid_riot_response),
    ("positive", 200, {"ip": "114.119.130.178"}, valid_riot_response_2),
    ("negative", 400, {"ip": "123"}, invalid_riot_response),
    ("negative", 400, {"ip": "abc"}, invalid_riot_response),
]

context_command_response_data = [
    ({"ip": "71.6.135.131"}, "positive", valid_ip_response, 200, valid_ip_response_expected),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "positive",
        {"ip": "71.6.135.131", "seen": False},
        200,  # NOSONAR
        {"address": "71.6.135.131", "seen": False},
    ),  # NOSONAR
    ({"ip": "123"}, "negative", "Invalid IP address: '123'", 200, "Invalid IP address: '123'"),  # NOSONAR
    ({"ip": "abc"}, "negative", "forbidden", 200, "Invalid IP address: 'abc'"),  # NOSONAR
]

valid_similar_response = {
    "ip": {
        "actor": "unknown",
        "asn": "AS4134",
        "city": "Beijing",
        "classification": "malicious",
        "country": "China",
        "country_code": "CN",
        "first_seen": "2023-05-29",
        "ip": "121.239.23.85",
        "last_seen": "2023-05-30",
        "organization": "CHINANET-BACKBONE"
    },
    "similar_ips": [
        {
            "actor": "unknown",
            "asn": "AS1221",
            "city": "Melbourne",
            "classification": "unknown",
            "country": "Australia",
            "country_code": "AU",
            "features": [
                "ports",
                "spoofable_bool"
            ],
            "first_seen": "2023-05-22",
            "ip": "1.145.159.157",
            "last_seen": "2023-05-23",
            "organization": "Telstra Corporation Ltd",
            "score": 1
        }
    ],
    "total": 32368
}

valid_similar_response_expected = copy.deepcopy(valid_similar_response)

similar_command_response_data = [
    ({"ip": "71.6.135.131"}, "positive", valid_similar_response, 200, valid_similar_response_expected),  # NOSONAR
    ({"ip": "45.95.147.229"}, "positive", {
        "ip": {
            "actor": "unknown",
            "asn": "AS49870",
            "city": "Amsterdam",
            "classification": "malicious",
            "country": "Netherlands",
            "country_code": "NL",
            "first_seen": "2023-05-11",
            "ip": "45.95.147.229",
            "last_seen": "2023-05-30",
            "organization": "Alsycon B.V."
        },
        "similar_ips": [],
        "total": 0
    }, 200, valid_similar_response_expected),  # NOSONAR
    ({"ip": "192.168.1.1"}, "negative", "Non-Routable IP address: '192.168.1.1'", 404, "Non-Routable IP address: "
                                                                                       "'192.168.1.1'"),  # NOSONAR
    ({"ip": "abc"}, "negative", "forbidden", 404, "Invalid IP address: 'abc'"),  # NOSONAR
]

valid_timeline_response = {
    "activity": [
        {
            "asn": "AS49870",
            "category": "hosting",
            "city": "Amsterdam",
            "classification": "unknown",
            "country": "Netherlands",
            "country_code": "NL",
            "destinations": [
                {
                    "country": "Albania",
                    "country_code": "AL"
                }
            ],
            "organization": "Alsycon B.V.",
            "protocols": [
                {
                    "app_protocol": "TELNET",
                    "port": 23,
                    "transport_protocol": "TCP"
                }
            ],
            "rdns": "tittle.life",
            "region": "North Holland",
            "spoofable": "true",
            "tags": [
                {
                    "category": "tool",
                    "description": "IP addresses with this tag have been observed using the ZMap Internet scanner.",
                    "intention": "unknown",
                    "name": "ZMap Client"
                }
            ],
            "timestamp": "2023-05-29T00:00:00Z",
            "tor": "false",
            "vpn": "false",
            "vpn_service": ""
        }
    ],
    "ip": "45.95.147.229",
    "metadata": {
        "end_time": "2023-05-30T18:43:30.604457229Z",
        "ip": "45.95.147.229",
        "limit": 50,
        "next_cursor": "",
        "start_time": "2023-05-29T00:00:00Z"
    }
}

valid_timeline_response_expected = copy.deepcopy(valid_timeline_response)

timeline_command_response_data = [
    ({"ip": "45.95.147.229"}, "positive", valid_timeline_response, 200, valid_timeline_response_expected),  # NOSONAR
    ({"ip": "61.30.129.190"}, "positive", {
        "activity": [],
        "ip": "61.30.129.190",
        "metadata": {
            "end_time": "2023-05-30T18:46:34.662311004Z",
            "ip": "61.30.129.190",
            "limit": 50,
            "next_cursor": "",
            "start_time": "2023-05-29T00:00:00Z"
        }
    }, 200, valid_timeline_response_expected),  # NOSONAR
    ({"ip": "192.168.1.1"}, "negative", "Non-Routable IP address: '192.168.1.1'", 404, "Non-Routable IP address: "
                                                                                       "'192.168.1.1'"),  # NOSONAR
    ({"ip": "abc"}, "negative", "forbidden", 404, "Invalid IP address: 'abc'"),  # NOSONAR
]

cve_command_response_data = [
    (
        {"cve": "CVE-1900-12345"},
        "positive",
        {
            "id": "CVE-1900-12345",
            "details": {
                "vulnerability_name": "Test",
                "vulnerability_description": "Test.",
                "cve_cvss_score": 8.6,
                "product": "Test",
                "vendor": "test",
                "published_to_nist_nvd": True
            },
            "timeline": {
                "cve_published_date": "2024-05-28T19:15:10Z",
                "cve_last_updated_date": "2024-05-31T16:04:09Z",
                "first_known_published_date": "2024-05-27T00:00:00Z",
                "cisa_kev_date_added": "2024-05-30T00:00:00Z"
            },
            "exploitation_details": {
                "attack_vector": "NETWORK",
                "exploit_found": True,
                "exploitation_registered_in_kev": True,
                "epss_score": 0.94237
            },
            "exploitation_stats": {
                "number_of_available_exploits": 60,
                "number_of_threat_actors_exploiting_vulnerability": 1,
                "number_of_botnets_exploiting_vulnerability": 0
            },
            "exploitation_activity": {
                "activity_seen": True,
                "benign_ip_count_1d": 0,
                "benign_ip_count_10d": 0,
                "benign_ip_count_30d": 0,
                "threat_ip_count_1d": 4,
                "threat_ip_count_10d": 10,
                "threat_ip_count_30d": 18
            }
        },
        200,
        {
            "id": "CVE-1900-12345",
            "details": {
                "vulnerability_name": "Test",
                "vulnerability_description": "Test.",
                "cve_cvss_score": 8.6,
                "product": "Test",
                "vendor": "test",
                "published_to_nist_nvd": True
            },
            "timeline": {
                "cve_published_date": "2024-05-28T19:15:10Z",
                "cve_last_updated_date": "2024-05-31T16:04:09Z",
                "first_known_published_date": "2024-05-27T00:00:00Z",
                "cisa_kev_date_added": "2024-05-30T00:00:00Z"
            },
            "exploitation_details": {
                "attack_vector": "NETWORK",
                "exploit_found": True,
                "exploitation_registered_in_kev": True,
                "epss_score": 0.94237
            },
            "exploitation_stats": {
                "number_of_available_exploits": 60,
                "number_of_threat_actors_exploiting_vulnerability": 1,
                "number_of_botnets_exploiting_vulnerability": 0
            },
            "exploitation_activity": {
                "activity_seen": True,
                "benign_ip_count_1d": 0,
                "benign_ip_count_10d": 0,
                "benign_ip_count_30d": 0,
                "threat_ip_count_1d": 4,
                "threat_ip_count_10d": 10,
                "threat_ip_count_30d": 18
            }
        }),
    ({"cve": "abce"}, "negative", {}, 400, "The provided ID does not match the format: CVE-XXXX-YYYYY")
]
