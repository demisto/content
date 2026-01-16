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
        "trust_level": "",
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
                "updated_at": "2025-06-24T21:35:56.342633Z",
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
            "destination_countries": ["Brazil"],
            "destination_country_codes": ["BR"],
        },
        "last_seen_timestamp": "2025-06-26 12:59:00",
    },
    "request_metadata": {},
}

valid_riot_ip_response = {
    "ip": "1.1.1.1",
    "business_service_intelligence": {
        "found": True,
        "category": "public_dns",
        "name": "Cloudflare Public DNS",
        "description": "Cloudflare, Inc. is an American web infrastructure and website security company, providing content delivery network (CDN) services, distributed denial of service (DDoS) mitigation, Internet security, and distributed domain name system (DNS) services. This is their public DNS offering.",
        "explanation": "Public DNS services are used as alternatives to ISP's name servers. You may see devices on your network communicating with Cloudflare Public DNS over port 53/TCP or 53/UDP to resolve DNS lookups.",
        "last_updated": "2025-06-26T13:10:55Z",
        "reference": "https://one.one.one.one",
        "trust_level": "1",
    },
    "internet_scanner_intelligence": {
        "last_seen": "",
        "found": False,
        "tags": [],
        "actor": "",
        "spoofable": False,
        "classification": "",
        "bot": False,
        "vpn": False,
        "vpn_service": "",
        "tor": False,
        "metadata": {
            "asn": "",
            "source_country": "",
            "source_country_code": "",
            "source_city": "",
            "domain": "",
            "rdns_parent": "",
            "rdns_validated": False,
            "organization": "",
            "category": "",
            "rdns": "",
            "os": "",
            "sensor_count": 0,
            "sensor_hits": 0,
            "region": "",
            "mobile": False,
            "single_destination": False,
            "destination_countries": [],
            "destination_country_codes": [],
            "destination_asns": [],
            "destination_cities": [],
            "carrier": "",
            "datacenter": "",
            "longitude": 0,
            "latitude": 0,
        },
        "last_seen_timestamp": "",
    },
    "request_metadata": {},
}

valid_ip_response_expected = copy.deepcopy(valid_ip_response)
valid_ip_response_expected["address"] = valid_ip_response["ip"]
del valid_ip_response_expected["ip"]

valid_riot_ip_response_expected = copy.deepcopy(valid_riot_ip_response)
valid_riot_ip_response_expected["address"] = valid_riot_ip_response["ip"]
del valid_riot_ip_response_expected["ip"]

# api_key, api_response, status_code, expected_output
test_module_data = [
    ("true_key", {"message": "pong"}, 200, "ok"),
    ("dummy_key", "forbidden", 401, "Unauthenticated. Check the configured API Key."),
    ("dummy_key", "", 429, "API Rate limit hit. Try after sometime."),
    (
        "dummy_key",
        "Dummy message",
        405,
        "Failed to execute  command.\n Error: Dummy message",
    ),
    (
        "dummy_key",
        "Dummy message",
        505,
        "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    ),
]



get_ip_reputation_score_data = [
    ("unknown", (0, "Unknown")),
    ("", (0, "Unknown")),
    ("benign", (1, "Good")),
    ("malicious", (3, "Bad")),
    ("dummy", (0, "Unknown")),
    ("suspicious", (2, "Suspicious")),
]

valid_ip_context_data = {
    "ip": "71.6.135.131",
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
            "updated_at": "2025-06-24T21:35:56.342633Z",
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
        "destination_countries": ["Brazil"],
        "destination_country_codes": ["BR"],
    },
    "last_seen_timestamp": "2025-06-26 12:59:00",
}

valid_ip_context_data_response = [
    {
        "MetaData": [
            "ASN: AS10439",
            "Source Country: United States",
            "Source Country Code: US",
            "source_city: San Diego",
            "domain: fiberalley.com",
            "rdns_parent: shodan.io",
            "rdns_validated: False",
            "Organization: CariNet, Inc.",
            "Category: hosting",
            "rDNS: soda.census.shodan.io",
            "Region: California",
            "mobile: False",
            "single_destination: False",
            "Destination Countries: ['Brazil']",
            "Destination Country Codes: ['BR']",
        ],
        "IP": "[71.6.135.131](https://viz.greynoise.io/ip/71.6.135.131)",
        "Last Seen": "2025-06-26",
        "Found": True,
        "Tags": ["ADB Check (suspicious - activity)"],
        "Actor": "Shodan.io",
        "Spoofable": False,
        "Classification": "benign",
        "BOT": False,
        "VPN": False,
        "Tor": False,
        "Last Seen Timestamp": "2025-06-26 12:59:00",
        "Internet Scanner": True,
        "Address": "71.6.135.131",
    }
]

# Create the proper input data for get_ip_context_data function

valid_ip_context_data["seen"] = valid_ip_context_data.get("found", False)
valid_ip_context_data["address"] = valid_ip_context_data["ip"]
valid_ip_context_data["ip"] = valid_ip_context_data["ip"]

# test trust-level
valid_ip_context_tl_data = copy.deepcopy(valid_ip_context_data)
valid_ip_context_tl_data["trust_level"] = "2"

valid_ip_response_tl = copy.deepcopy(valid_ip_response)
valid_ip_response_tl["business_service_intelligence"]["found"] = True
valid_ip_response_tl["business_service_intelligence"]["trust_level"] = "2"
valid_ip_response_tl["business_service_intelligence"]["logo_url"] = "test_url"

valid_ip_context_data_response_tl = copy.deepcopy(valid_ip_context_data_response)
valid_ip_context_data_response_tl[0]["Trust Level"] = "2"

valid_ip_response_expected_tl = copy.deepcopy(valid_ip_response_expected)
valid_ip_response_expected_tl["business_service_intelligence"]["found"] = True
valid_ip_response_expected_tl["business_service_intelligence"]["trust_level"] = "2"

# test malicious description
valid_ip_response_md_data = copy.deepcopy(valid_ip_response)
valid_ip_response_md_data["internet_scanner_intelligence"]["classification"] = "malicious"

valid_ip_response_expected_md = copy.deepcopy(valid_ip_response_expected)
valid_ip_response_expected_md["internet_scanner_intelligence"]["classification"] = "malicious"

get_ip_context_data_data = [
    ([valid_ip_context_data], valid_ip_context_data_response),
    ([valid_ip_context_tl_data], valid_ip_context_data_response_tl),
]

valid_tag_data = [
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
                "updated_at": "2025-06-24T21:35:56.342633Z",
            }
        ]

valid_tag_data_response = ["ADB Check (suspicious - activity)"]

get_ip_tag_names_data = [(valid_tag_data, valid_tag_data_response)]


ip_reputation_command_data = [
    (
        {"ip": "71.6.135.131"},
        "positive",
        valid_ip_response,
        200,
        valid_ip_response_expected,
    ),
    (
        {"ip": "71.6.135.132"},
        "positive",
        valid_ip_response_md_data,
        200,
        valid_ip_response_expected_md,
    ),
        (
        {"ip": "71.6.135.133"},
        "positive",
        valid_ip_response_tl,
        200,
        valid_ip_response_expected_tl,
    ),
    (
        {"ip": "1.1.1.1"},
        "positive",
        valid_riot_ip_response,
        200,
        valid_riot_ip_response_expected,
    ),
    (
        {"ip": "71.6.135.131"},
        "positive",
        {
            "ip": "71.6.135.131",
            "internet_scanner_intelligence": {"found": False},
            "business_service_intelligence": {"found": False},
        },
        404,
        {
            "address": "71.6.135.131",
            "internet_scanner_intelligence": {"found": False},
            "business_service_intelligence": {"found": False},
        },
    ),
    (
        {"ip": "71.6.135.131"},
        "negative",
        "invalid ip response",
        400,
        "Invalid response from GreyNoise. Response: (400, 'invalid ip response')",
    ),
    (
        {"ip": "71.6.135.131"},
        "negative",
        "forbidden",
        401,
        "Invalid response from GreyNoise. Response: (401, 'forbidden')",
    ),
    (
        {"ip": "71.6.135.131"},
        "negative",
        {},
        429,
        "Invalid response from GreyNoise. Response: ",
    ),
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
        505,
        "Invalid response from GreyNoise. Response: (505, {})",
    ),
    (
        {"ip": "5844.2204.2191.2471"},
        "negative",
        {},
        200,
        "Invalid response from GreyNoise. Response: Invalid IP address: '5844.2204.2191.2471'",
    ),
]