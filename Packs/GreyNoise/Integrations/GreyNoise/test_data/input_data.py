import copy

valid_ip_response = {
  "ip": "71.6.135.131",
  "business_service_intelligence": {
    "found": False,
    "category": "",
    "name": "",
    "description": "",
    "explanation": "",
    "last_updated": "",
    "reference": "",
    "trust_level": ""
  },
  "internet_scanner_intelligence": {
    "last_seen": "2025-06-26",
    "found": True,
    "tags": [
      {
        "id": "36c75a5a-d4f8-46b3-b597-e0cbbf1ac3a0",
        "slug": "adb-check",
        "name": "ADB Check",
        "description": "IP addresses with this tag have been observed checking for the existence of the Android Debug Bridge protocol.",
        "category": "activity",
        "intention": "suspicious",
        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1900-12345"],
        "cves": ["CVE-1900-12345"],
        "recommend_block": False,
        "created": "2021-08-26",
        "updated_at": "2025-06-24T21:35:56.342633Z"
      }
    ],
    "actor": "Shodan.io",
    "spoofable": False,
    "classification": "benign",
    "bot": False,
    "vpn": False,
    "vpn_service": "",
    "tor": False,
    "metadata": {
      "asn": "AS10439",
      "source_country": "United States",
      "source_country_code": "US",
      "source_city": "San Diego",
      "domain": "fiberalley.com",
      "rdns_parent": "shodan.io",
      "rdns_validated": False,
      "organization": "CariNet, Inc.",
      "category": "hosting",
      "rdns": "soda.census.shodan.io",
      "os": "",
      "region": "California",
      "mobile": False,
      "single_destination": False,
      "destination_countries": [
        "Brazil"
      ],
      "destination_country_codes": [
        "BR"
      ]
    },
    "last_seen_timestamp": "2025-06-26 12:59:00"
  }
}

valid_ip_response_expected = copy.deepcopy(valid_ip_response)
valid_ip_response_expected["address"] = valid_ip_response["ip"]
del valid_ip_response_expected["ip"]

valid_ip_response_expected_modified = copy.deepcopy(valid_ip_response_expected["internet_scanner_intelligence"])
valid_ip_response_expected_modified["seen"] = True
valid_ip_response_expected_modified["address"] = valid_ip_response["ip"]
valid_ip_response_expected_modified["ip"] = valid_ip_response["ip"]
valid_ip_response_expected_unlicensed_business_service = copy.deepcopy(valid_ip_response_expected_modified)
valid_ip_response_expected_unlicensed_business_service["business_service_status"] = (
    "Business Service Intelligence data is not available with the current license."
)

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

def ip_response_with_business_service(business_service):
    """Return a scanner hit whose business service intelligence is empty or absent."""
    payload = copy.deepcopy(valid_ip_response)
    if business_service == "missing":
        payload.pop("business_service_intelligence", None)
    else:
        payload["business_service_intelligence"] = business_service
    return payload


ip_reputation_command_data = [
    ({"ip": "71.6.135.131"}, "positive", valid_ip_response, 200, valid_ip_response_expected_modified),
    (
        {"ip": "71.6.135.131"},
        "positive",
        ip_response_with_business_service({}),
        200,
        valid_ip_response_expected_modified,
    ),
    (
        {"ip": "71.6.135.131"},
        "positive",
        ip_response_with_business_service(None),
        200,
        valid_ip_response_expected_modified,
    ),
    (
        {"ip": "71.6.135.131"},
        "positive",
        ip_response_with_business_service("missing"),
        200,
        valid_ip_response_expected_modified,
    ),
    (
        {"ip": "71.6.135.131"},
        "positive",
        ip_response_with_business_service({"found": None}),
        200,
        valid_ip_response_expected_unlicensed_business_service,
    ),
    (
        {"ip": "71.6.135.131"},
        "positive",
        {"ip": "71.6.135.131", "internet_scanner_intelligence": {"found": False}, "business_service_intelligence": {}},
        200,
        {"found": False, "seen": False, "address": "71.6.135.131", "ip": "71.6.135.131", "riot": False},
    ),
    (
        {"ip": "71.6.135.131"},
        "positive",
        {"ip": "71.6.135.131", "internet_scanner_intelligence": {"found": False}, "business_service_intelligence": {"found": False}},
        200,
        {"found": False, "seen": False, "address": "71.6.135.131", "ip": "71.6.135.131", "riot": False},
    ),
    (
        {"ip": "71.6.135.131"},
        "negative",
        "invalid ip response",
        200,
        "Invalid response from GreyNoise. Response: invalid ip response",
    ),
    ({"ip": "71.6.135.131"}, "negative", "forbidden", 401, "Invalid response from GreyNoise. Response: (401, 'forbidden')"),
    ({"ip": "71.6.135.131"}, "negative", {}, 429, "Invalid response from GreyNoise. Response: "),
    (
        {"ip": "71.6.135.131"},
        "negative",
        "Dummy message",
        405,
        "Invalid response from GreyNoise. Response: (405, 'Dummy message')",
    ),
    (
        {"ip": "71.6.135.131"},
        "negative",
        {},
        500,
        "Invalid response from GreyNoise. Response: (500, {})",
    ),
    ({"ip": "5844.2204.2191.2471"}, "negative", {"error": "invalid ip submitted"}, 400, "Invalid response from GreyNoise. Response: (400, {'error': 'invalid ip submitted'})"),
]

get_ip_reputation_score_data = [
    ("unknown", (0, "Unknown")),
    ("", (0, "Unknown")),
    ("benign", (1, "Good")),
    ("malicious", (3, "Bad")),
    ("dummy", (0, "Unknown")),
]

valid_quick_response = [
    {
        "ip": "71.5.135.131",
        "business_service_intelligence": {
            "found": False,
            "trust_level": ""
            },
        "internet_scanner_intelligence": {
            "found": True,
            "classification": "benign"
        }
    }
]

valid_multiple_qc_resp = [
    {
        "ip": "71.5.135.131",
        "business_service_intelligence": {
            "found": False,
            "trust_level": ""
            },
        "internet_scanner_intelligence": {
            "found": True,
            "classification": "benign"
            }
    },
    {
        "ip": "8.8.8.8",
        "business_service_intelligence": {
            "found": False,
            "trust_level": ""
            },
        "internet_scanner_intelligence": {
            "found": True,
        "classification": "benign"
            }
    },
]
valid_quick_response_expected = copy.deepcopy(valid_quick_response)
for resp in valid_quick_response_expected:
    resp["address"] = resp["ip"]
    del resp["ip"]

valid_multiple_qc_resp_expected = copy.deepcopy(valid_multiple_qc_resp)
for resp in valid_multiple_qc_resp_expected:
    resp["address"] = resp["ip"]
    del resp["ip"]

# ip, test_scenario, api_response, status_code, expected_output
empty_business_service_quick_response = [
    {
        "ip": "71.5.135.131",
        "business_service_intelligence": {},
        "internet_scanner_intelligence": {"found": True, "classification": "benign"},
    }
]
empty_business_service_quick_response_expected = [
    {
        "address": "71.5.135.131",
        "internet_scanner_intelligence": {"found": True, "classification": "benign"},
    }
]
null_business_service_quick_response = [
    {
        "ip": "71.5.135.131",
        "business_service_intelligence": None,
        "internet_scanner_intelligence": {"found": True, "classification": "benign"},
    }
]
unlicensed_business_service_quick_response = [
    {
        "ip": "71.5.135.131",
        "business_service_intelligence": {"found": None, "trust_level": ""},
        "internet_scanner_intelligence": {"found": True, "classification": "unknown"},
    }
]
unlicensed_business_service_quick_response_expected = [
    {
        "address": "71.5.135.131",
        "business_service_intelligence": {
            "trust_level": "",
            "business_service_status": "Business Service Intelligence data is not available with the current license.",
        },
        "internet_scanner_intelligence": {"found": True, "classification": "unknown"},
    }
]

ip_quick_check_command_data = [
    ({"ip": "71.5.135.131"}, "positive", valid_quick_response, 200, valid_quick_response_expected),
    (
        {"ip": "71.5.135.131"},
        "positive",
        empty_business_service_quick_response,
        200,
        empty_business_service_quick_response_expected,
    ),
    (
        {"ip": "71.5.135.131"},
        "positive",
        null_business_service_quick_response,
        200,
        empty_business_service_quick_response_expected,
    ),
    (
        {"ip": "71.5.135.131"},
        "positive",
        unlicensed_business_service_quick_response,
        200,
        unlicensed_business_service_quick_response_expected,
    ),
    (
        {"ip": "71.5.135.131,8.8.8.8"},
        "positive",
        valid_multiple_qc_resp,
        200,
        valid_multiple_qc_resp_expected,
    ),
    (
        {"ip": "71.6.135.131"},
        "custom",
        "invalid ip response",
        200,
        "Invalid response from GreyNoise. Response: invalid ip response",
    ),
    (
        {"ip": "71.6.135.131"},
        "negative",
        "forbidden",
        401,
        "Unauthenticated. Check the configured API Key.",
    ),
    ({"ip": "71.6.135.131"}, "negative", [], 429, "API Rate limit hit. Try after sometime."),
    (
        {"ip": "71.6.135.131"},
        "negative",
        "Dummy message",
        405,
        "Failed to execute greynoise-ip-quick-check command.\n Error: Dummy message",
    ),
    (
        {"ip": "71.6.135.131"},
        "negative",
        [],
        505,
        "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    ),
    ({"ip": "5844.2204.2191.2471"}, "negative", [], 200, "Invalid IP address: '5844.2204.2191.2471'"),
    ({"ip": ""}, "negative", [], 200, "Invalid IP address: ''"),
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
            "ip": "71.6.135.131",
            "business_service_intelligence": {
                "found": False,
                "category": "",
                "name": "",
                "description": "",
                "explanation": "",
                "last_updated": "",
                "reference": "",
                "trust_level": ""
            },
            "internet_scanner_intelligence": {
                "last_seen": "2025-06-26",
                "found": True,
                "tags": [
                {
                    "id": "36c75a5a-d4f8-46b3-b597-e0cbbf1ac3a0",
                    "slug": "adb-check",
                    "name": "ADB Check",
                    "description": "IP addresses with this tag have been observed checking for the existence of the Android Debug Bridge protocol.",
                    "category": "activity",
                    "intention": "suspicious",
                    "references": [],
                    "cves": [],
                    "recommend_block": False,
                    "created": "2021-08-26",
                    "updated_at": "2025-06-24T21:35:56.342633Z"
                }
                ],
                "actor": "Shodan.io",
                "spoofable": False,
                "classification": "benign",
                "bot": False,
                "vpn": False,
                "vpn_service": "",
                "tor": False,
                "metadata": {
                "asn": "AS10439",
                "source_country": "United States",
                "source_country_code": "US",
                "source_city": "San Diego",
                "domain": "fiberalley.com",
                "rdns_parent": "shodan.io",
                "rdns_validated": False,
                "organization": "CariNet, Inc.",
                "category": "hosting",
                "rdns": "soda.census.shodan.io",
                "os": "",
                "region": "California",
                "mobile": False,
                "single_destination": False,
                "destination_countries": [
                    "Brazil"
                ],
                "destination_country_codes": [
                    "BR"
                ]
                },
                "last_seen_timestamp": "2025-06-26 12:59:00"
            }
            }
    ],
    "message": "ok",
    "query": "dummy_query",
    "scroll": "dummy_scroll",
    "request_metadata": {
        "message": "ok",
        "count": 1,
        "complete": False,
        "adjusted_query": "dummy_query",
        "scroll": "dummy_scroll"
    }
}

valid_query_response_expected = copy.deepcopy(valid_query_response)
for each in valid_query_response_expected.get("data"):  # type: ignore
    each["address"] = each["ip"]
    del each["ip"]

# Create the expected output structure that matches what the implementation returns
valid_query_response_expected_output = {
    "GreyNoise.IP(val.address && val.address == obj.address)": valid_query_response_expected["data"],
    "GreyNoise.Query(val.query && val.query == obj.query)": {
        "complete": valid_query_response["request_metadata"]["complete"],
        "count": valid_query_response["request_metadata"]["count"],
        "message": valid_query_response["request_metadata"]["message"],
        "query": valid_query_response["request_metadata"]["adjusted_query"],
        "scroll": valid_query_response["request_metadata"]["scroll"],
    }
}

query_command_data: list = [
    ({}, "positive", valid_query_response, 200, valid_query_response_expected_output),
    ({}, "negative", "dummy message", 400, "Invalid response from GreyNoise. Response: (400, 'dummy message')"),
    (
        {},
        "negative",
        {"request_metadata": {"message": "dummy_message"}},
        200,
        "GreyNoise request failed. Reason: dummy_message",
    ),
    ({}, "negative", "forbidden", 401, "Invalid response from GreyNoise. Response: (401, 'forbidden')"),
    ({}, "negative", {}, 429, "Invalid response from GreyNoise. Response: API Limit Reached"),
    ({}, "negative", "Dummy message", 405, "Invalid response from GreyNoise. Response: (405, 'Dummy message')"),
    (
        {},
        "negative",
        {},
        505,
        "Invalid response from GreyNoise. Response: (505, [])",
    ),
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
    ({}, "positive", valid_stats_response, 200, valid_stats_response_expected),
    ({}, "negative", "dummy message", 400, "Invalid response from GreyNoise. Response: (400, 'dummy message')"),
    (
        {},
        "positive",
        invalid_stats_response,
        200,
        {"count": 0, "query": "classification:sdcsdc spoofable:false"},
    ),
    ({}, "negative", "forbidden", 401, "Invalid response from GreyNoise. Response: (401, 'forbidden')"),
    ({}, "negative", {}, 429, "Invalid response from GreyNoise. Response: API Limit Reached"),
    ({}, "negative", "Dummy message", 405, "Invalid response from GreyNoise. Response: (405, 'Dummy message')"),
    (
        {},
        "negative",
        {},
        505,
        "Invalid response from GreyNoise. Response: (505, [])",
    ),
]

valid_ip_context_data = {
    "ip": "71.6.135.131",
    "business_service_intelligence": {
        "found": False,
        "category": "",
        "name": "",
        "description": "",
        "explanation": "",
        "last_updated": "",
        "reference": "",
        "trust_level": ""
    },
    "internet_scanner_intelligence": {
        "last_seen": "2025-06-26",
        "found": True,
        "tags": [
        {
            "id": "36c75a5a-d4f8-46b3-b597-e0cbbf1ac3a0",
            "slug": "adb-check",
            "name": "ADB Check",
            "description": "IP addresses with this tag have been observed checking for the existence of the Android Debug Bridge protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": False,
            "created": "2021-08-26",
            "updated_at": "2025-06-24T21:35:56.342633Z"
        }
        ],
        "actor": "Shodan.io",
        "spoofable": False,
        "classification": "benign",
        "bot": False,
        "vpn": False,
        "vpn_service": "",
        "tor": False,
        "metadata": {
        "asn": "AS10439",
        "source_country": "United States",
        "source_country_code": "US",
        "source_city": "San Diego",
        "domain": "fiberalley.com",
        "rdns_parent": "shodan.io",
        "rdns_validated": False,
        "organization": "CariNet, Inc.",
        "category": "hosting",
        "rdns": "soda.census.shodan.io",
        "os": "",
        "region": "California",
        "mobile": False,
        "single_destination": False,
        "destination_countries": [
            "Brazil"
        ],
        "destination_country_codes": [
            "BR"
        ]
        },
        "last_seen_timestamp": "2025-06-26 12:59:00"
    }
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
        "IP": "[71.6.135.131](https://viz.greynoise.io/ip/71.6.135.131)",
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
        "internet_scanner_intelligence": {"found": False},
        "business_service_intelligence": {
        "found": True,
        "category": "public_dns",
        "name": "Google Public DNS",
        "description": "Google's global domain name system (DNS) resolution service.",
        "explanation": "Public DNS services are used as alternatives to ISP's name servers. "
        "You may see devices on your network communicating with Google Public DNS over port "
        "53/TCP or 53/UDP to resolve DNS lookups.",
        "last_updated": "2021-04-12T09:55:37Z",
        "reference": "https://developers.google.com/speed/public-dns/docs/isp#alternative",}
    },
    "readable": "### IP: 8.8.8.8 found with Reputation: Unknown\n#### Belongs to Common Business Service: "
    "Google Public DNS\n### GreyNoise Business Service Intelligence Lookup\n|IP|Business Service|Category|Name|Trust Level|Description|Last Updated|\n"
    "|---|---|---|---|---|---|---|\n| [8.8.8.8](https://viz.greynoise.io/ip/8.8.8.8) | true | public_dns | Google Public DNS "
    "|  | Google's global domain name system (DNS) resolution service. | 2021-04-12T09:55:37Z |\n",
}

valid_riot_response_2 = {
    "output": {"ip": "114.119.130.178", "internet_scanner_intelligence": {"found": False}, "business_service_intelligence": {"found": False}},
    "readable": "### IP: 114.119.130.178 Not Associated with a Business Service"
    "\n### GreyNoise Business Service Intelligence Lookup\n|IP|Business Service|\n|---|---|\n| 114.119.130.178 | false |\n",
}

riot_command_response_data = [
    ("positive", 200, {"ip": "8.8.8.8"}, valid_riot_response),
    ("positive", 200, {"ip": "114.119.130.178"}, valid_riot_response_2),
    ("negative", 400, {"ip": "123"}, "Invalid response from GreyNoise. Response: (400, 'invalid ip submitted')"),
    ("negative", 400, {"ip": "abc"}, "Invalid response from GreyNoise. Response: (400, 'invalid ip submitted')"),
]

valid_context_response_expected = copy.deepcopy(valid_ip_response_expected["internet_scanner_intelligence"])
valid_context_response_expected["seen"] = True
valid_context_response_expected["ip"] = "71.6.135.131"
valid_context_response_expected["address"] = "71.6.135.131"

context_command_response_data = [
    ({"ip": "71.6.135.131"}, "positive", valid_ip_response, 200, valid_context_response_expected),
    (
        {"ip": "71.6.135.131"},
        "positive",
        {"ip": "71.6.135.131", "business_service_intelligence": {
            "found": False,
            "trust_level": ""
            },
        "internet_scanner_intelligence": {
            "found": False,
            "classification": ""
            }},
        200,
       {
        "ip": "71.6.135.131",
        "found": False,
        "seen": False,
        "address": "71.6.135.131",
        "classification": ""
        },
    ),
    ({"ip": "123"}, "negative", {"error":"invalid ip submitted"}, 400, "Invalid response from GreyNoise. Response: (400, 'invalid ip submitted')"),
    ({"ip": "abc"}, "negative", {"error":"invalid ip submitted"}, 400, "Invalid response from GreyNoise. Response: (400, 'invalid ip submitted')"),
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
        "organization": "CHINANET-BACKBONE",
    },
    "similar_ips": [
        {
            "actor": "unknown",
            "asn": "AS1221",
            "city": "Melbourne",
            "classification": "unknown",
            "country": "Australia",
            "country_code": "AU",
            "features": ["ports", "spoofable_bool"],
            "first_seen": "2023-05-22",
            "ip": "1.145.159.157",
            "last_seen": "2023-05-23",
            "organization": "Telstra Corporation Ltd",
            "score": 1,
        }
    ],
    "total": 32368,
}

valid_similar_response_expected = copy.deepcopy(valid_similar_response)

similar_command_response_data = [
    ({"ip": "71.6.135.131"}, "positive", valid_similar_response, 200, valid_similar_response_expected),
    (
        {"ip": "45.95.147.229"},
        "positive",
        {
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
                "organization": "Alsycon B.V.",
            },
            "similar_ips": [],
            "total": 0,
        },
        200,
        valid_similar_response_expected,
    ),
    (
        {"ip": "192.168.1.1"},
        "negative",
        "Non-Routable IP address: '192.168.1.1'",
        404,
        "Failed to execute greynoise-similar command.\n Error: \"Non-Routable IP address: '192.168.1.1'\"",
    ),
    ({"ip": "abc"}, "negative", "forbidden", 404, "Failed to execute greynoise-similar command.\n Error: forbidden"),
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
            "destinations": [{"country": "Albania", "country_code": "AL"}],
            "organization": "Alsycon B.V.",
            "protocols": [{"app_protocol": "TELNET", "port": 23, "transport_protocol": "TCP"}],
            "rdns": "tittle.life",
            "region": "North Holland",
            "spoofable": "true",
            "tags": [
                {
                    "category": "tool",
                    "description": "IP addresses with this tag have been observed using the ZMap Internet scanner.",
                    "intention": "unknown",
                    "name": "ZMap Client",
                }
            ],
            "timestamp": "2023-05-29T00:00:00Z",
            "tor": "false",
            "vpn": "false",
            "vpn_service": "",
        }
    ],
    "ip": "45.95.147.229",
    "metadata": {
        "end_time": "2023-05-30T18:43:30.604457229Z",
        "ip": "45.95.147.229",
        "limit": 50,
        "next_cursor": "",
        "start_time": "2023-05-29T00:00:00Z",
    },
}

valid_timeline_response_expected = copy.deepcopy(valid_timeline_response)

timeline_command_response_data = [
    ({"ip": "45.95.147.229"}, "positive", valid_timeline_response, 200, valid_timeline_response_expected),
    (
        {"ip": "61.30.129.190"},
        "positive",
        {
            "activity": [],
            "ip": "61.30.129.190",
            "metadata": {
                "end_time": "2023-05-30T18:46:34.662311004Z",
                "ip": "61.30.129.190",
                "limit": 50,
                "next_cursor": "",
                "start_time": "2023-05-29T00:00:00Z",
            },
        },
        200,
        valid_timeline_response_expected,
    ),
    (
        {"ip": "192.168.1.1"},
        "negative",
        "Non-Routable IP address: '192.168.1.1'",
        404,
        "Failed to execute greynoise-timeline command.\n Error: \"Non-Routable IP address: '192.168.1.1'\"",
    ),
    ({"ip": "abc"}, "negative", "forbidden", 404, "Failed to execute greynoise-timeline command.\n Error: forbidden"),
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
                "published_to_nist_nvd": True,
            },
            "timeline": {
                "cve_published_date": "2024-05-28T19:15:10Z",
                "cve_last_updated_date": "2024-05-31T16:04:09Z",
                "first_known_published_date": "2024-05-27T00:00:00Z",
                "cisa_kev_date_added": "2024-05-30T00:00:00Z",
            },
            "exploitation_details": {
                "attack_vector": "NETWORK",
                "exploit_found": True,
                "exploitation_registered_in_kev": True,
                "epss_score": 0.94237,
            },
            "exploitation_stats": {
                "number_of_available_exploits": 60,
                "number_of_threat_actors_exploiting_vulnerability": 1,
                "number_of_botnets_exploiting_vulnerability": 0,
            },
            "exploitation_activity": {
                "activity_seen": True,
                "benign_ip_count_1d": 0,
                "benign_ip_count_10d": 0,
                "benign_ip_count_30d": 0,
                "threat_ip_count_1d": 4,
                "threat_ip_count_10d": 10,
                "threat_ip_count_30d": 18,
            },
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
                "published_to_nist_nvd": True,
            },
            "timeline": {
                "cve_published_date": "2024-05-28T19:15:10Z",
                "cve_last_updated_date": "2024-05-31T16:04:09Z",
                "first_known_published_date": "2024-05-27T00:00:00Z",
                "cisa_kev_date_added": "2024-05-30T00:00:00Z",
            },
            "exploitation_details": {
                "attack_vector": "NETWORK",
                "exploit_found": True,
                "exploitation_registered_in_kev": True,
                "epss_score": 0.94237,
            },
            "exploitation_stats": {
                "number_of_available_exploits": 60,
                "number_of_threat_actors_exploiting_vulnerability": 1,
                "number_of_botnets_exploiting_vulnerability": 0,
            },
            "exploitation_activity": {
                "activity_seen": True,
                "benign_ip_count_1d": 0,
                "benign_ip_count_10d": 0,
                "benign_ip_count_30d": 0,
                "threat_ip_count_1d": 4,
                "threat_ip_count_10d": 10,
                "threat_ip_count_30d": 18,
            },
        },
    ),
    ({"cve": "abce"}, "negative", {}, 400, "Invalid CVE ID format: 'abce'"),
]


# Real API response: business_service_intelligence.found is null, scanner hit present.
real_api_sample_null_found = {'ip': '45.83.65.120', 'business_service_intelligence': {'found': None, 'category': '', 'name': '', 'description': '', 'explanation': '', 'last_updated': '', 'reference': '', 'trust_level': ''}, 'internet_scanner_intelligence': {'first_seen': '', 'last_seen': '2026-11-13', 'found': True, 'tags': [{'id': '804e348c-2a55-46f5-bad5-a521f0dd8571', 'slug': 'ping-scanner', 'name': 'Ping Scanner', 'description': 'IP addresses with this tag have been observed scanning the Internet for live hosts using ICMP packets.', 'category': 'activity', 'intention': 'unknown', 'references': [], 'cves': [], 'recommend_block': False, 'created': '', 'updated_at': '2026-03-12T16:28:32Z'}, {'id': 'd0e29be3-fda4-4ae7-ae0c-4833ab1d07d1', 'slug': 'icmpv4-protocol', 'name': 'ICMPv4 Protocol', 'description': 'IP addresses with this tag have been observed attempting to connect using the ICMPv4 protocol, which is a control and error-reporting protocol used by IPv4 networks for operations like echo (ping), destination unreachable, and routing diagnostics.', 'category': 'protocol', 'intention': 'unknown', 'references': [], 'cves': [], 'recommend_block': False, 'created': '', 'updated_at': '2026-03-12T16:28:32Z'}], 'tag_volumes': [{'tag_id': '804e348c-2a55-46f5-bad5-a521f0dd8571', 'session_count': 600000}, {'tag_id': 'd0e29be3-fda4-4ae7-ae0c-4833ab1d07d1', 'session_count': 600000}], 'actor': 'unknown', 'spoofable': True, 'classification': 'unknown', 'cves': [], 'callback_ips': [], 'vpn': False, 'vpn_service': '', 'tor': False, 'metadata': {'asn': 'AS132203', 'asn_subnet': '', 'source_country': 'Germany', 'source_country_code': 'DE', 'source_city': 'Frankfurt am Main', 'domain': 'tencent.com', 'rdns_parent': '', 'rdns_validated': False, 'organization': 'Tencent Building, Kejizhongyi Avenue', 'category': 'hosting', 'rdns': '', 'os': '', 'sensor_count': 0, 'sensor_hits': 0, 'region': 'Hesse', 'mobile': False, 'single_destination': False, 'destination_countries': ['United Arab Emirates', 'Albania', 'Argentina', 'Austria', 'Australia', 'Azerbaijan', 'Belgium', 'Brazil', 'Canada', 'Switzerland', 'Chile', 'Czech Republic', 'Germany', 'Denmark', 'Algeria', 'Egypt', 'Spain', 'France', 'United Kingdom', 'Hong Kong', 'Hungary', 'Indonesia', 'India', 'Iceland', 'Japan', 'South Korea', 'Luxembourg', 'Moldova', 'Montenegro', 'Mexico', 'Malaysia', 'Netherlands', 'Oman', 'Panama', 'Poland', 'Romania', 'Serbia', 'Saudi Arabia', 'Sweden', 'Singapore', 'Thailand', 'Taiwan', 'United States', 'South Africa'], 'destination_country_codes': ['AE', 'AL', 'AR', 'AT', 'AU', 'AZ', 'BE', 'BR', 'CA', 'CH', 'CL', 'CZ', 'DE', 'DK', 'DZ', 'EG', 'ES', 'FR', 'GB', 'HK', 'HU', 'ID', 'IN', 'IS', 'JP', 'KR', 'LU', 'MD', 'ME', 'MX', 'MY', 'NL', 'OM', 'PA', 'PL', 'RO', 'RS', 'SA', 'SE', 'SG', 'TH', 'TW', 'US', 'ZA'], 'destination_asns': [], 'destination_cities': [], 'carrier': '', 'datacenter': '', 'longitude': 0, 'latitude': 0}, 'raw_data': {'scan': [], 'ja3': [], 'hassh': [], 'http': {'md5': [], 'cookie_keys': [], 'ja4h': [], 'request_authorization': [], 'request_cookies': [], 'request_header': [], 'method': [], 'path': [], 'request_origin': [], 'useragent': []}, 'source': {'bytes': 0, 'sessions': 600000}, 'tls': {'cipher': [], 'ja4': []}, 'ssh': {'key': [], 'ja4ssh': []}, 'tcp': {'ja4t': [], 'ja4l': []}}, 'last_seen_timestamp': '2026-11-13 18:01:27', 'last_seen_malicious': '', 'last_seen_suspicious': '', 'last_seen_benign': ''}, 'request_metadata': {'restricted_fields': ['asn_subnet', 'body_md5_hash', 'business_service_intelligence', 'bytes', 'callback_ips', 'cipher', 'cookie_keys', 'cve', 'destination_asns', 'destination_cities', 'first_seen', 'hassh_fingerprint', 'hassh_port', 'ja3_fingerprint', 'ja3_port', 'ja4', 'ja4h', 'ja4l', 'ja4ssh', 'ja4t', 'key', 'last_seen_benign', 'last_seen_malicious', 'last_seen_suspicious', 'os', 'product', 'profile_ids', 'profiles', 'request_authorization_header', 'request_cookies', 'request_header_values', 'request_method', 'request_origin_header', 'scan_ports', 'scan_protocols', 'sensor_counts', 'sensor_hits', 'source_latitude', 'source_longitude', 'user_agent', 'vendor', 'web_paths']}}

# Real API response: business service found, no internet scanner activity.
real_api_sample_business_service = {'ip': '1.1.2.2', 'business_service_intelligence': {'found': True, 'category': 'public_dns', 'name': 'Cloudflare Public DNS', 'description': 'Cloudflare, Inc. is an American web infrastructure and website security company, providing content delivery network (CDN) services, distributed denial of service (DDoS) mitigation, Internet security, and distributed domain name system (DNS) services. This is their public DNS offering.', 'explanation': "Public DNS services are used as alternatives to ISP's name servers. You may see devices on your network communicating with Cloudflare Public DNS over port 53/TCP or 53/UDP to resolve DNS lookups.", 'last_updated': '2026-11-13T00:00:00Z', 'reference': 'https://one.one.one.one', 'trust_level': '1'}, 'internet_scanner_intelligence': {'first_seen': '', 'last_seen': '', 'found': False, 'tags': [], 'actor': '', 'spoofable': False, 'classification': '', 'cves': [], 'callback_ips': [], 'vpn': False, 'vpn_service': '', 'tor': False, 'metadata': {'asn': '', 'asn_subnet': '', 'source_country': '', 'source_country_code': '', 'source_city': '', 'domain': '', 'rdns_parent': '', 'rdns_validated': False, 'organization': '', 'category': '', 'rdns': '', 'os': '', 'sensor_count': 0, 'sensor_hits': 0, 'region': '', 'mobile': False, 'single_destination': False, 'destination_countries': [], 'destination_country_codes': [], 'destination_asns': [], 'destination_cities': [], 'carrier': '', 'datacenter': '', 'longitude': 0, 'latitude': 0}, 'raw_data': {'scan': [], 'ja3': [], 'hassh': [], 'http': {'md5': [], 'cookie_keys': [], 'ja4h': [], 'request_authorization': [], 'request_cookies': [], 'request_header': [], 'method': [], 'path': [], 'request_origin': [], 'useragent': []}, 'source': {'bytes': 0}, 'tls': {'cipher': [], 'ja4': []}, 'ssh': {'key': [], 'ja4ssh': []}, 'tcp': {'ja4t': [], 'ja4l': []}}, 'last_seen_timestamp': '', 'last_seen_malicious': '', 'last_seen_suspicious': '', 'last_seen_benign': ''}, 'request_metadata': {'restricted_fields': []}}
