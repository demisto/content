import copy

valid_ip_response = {
    "ip": "71.6.135.131",
    "noise": True,
    "riot": False,
    "classification": "benign",
    "name": "Shodan.io",
    "link": "https://viz.greynoise.io/ip/71.6.135.131",
    "last_seen": "2021-05-10",
    "message": "Success",
}

valid_riot_ip_response = {
    "ip": "1.1.1.1",
    "noise": False,
    "riot": True,
    "classification": "benign",
    "name": "CloudFlare",
    "link": "https://viz.greynoise.io/ip/1.1.1.1",
    "last_seen": "2021-05-10",
    "message": "Success",
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

ip_reputation_command_data = [
    (
        {"ip": "71.6.135.131"},
        "positive",
        valid_ip_response,
        200,
        valid_ip_response_expected,
    ),  # NOSONAR
    (
        {"ip": "1.1.1.1"},
        "positive",
        valid_riot_ip_response,
        200,
        valid_riot_ip_response_expected,
    ),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "positive",
        {"ip": "71.6.135.131", "noise": False},
        200,  # NOSONAR
        {"address": "71.6.135.131", "noise": False},
    ),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "negative",
        "invalid ip response",
        200,  # NOSONAR
        "Invalid response from GreyNoise. Response: invalid ip response",
    ),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "negative",
        "forbidden",
        401,
        "Unauthenticated. Check the configured API Key.",
    ),  # NOSONAR
    (
        {"ip": "71.6.135.131"},
        "negative",
        {},
        429,
        "API Rate limit hit. Try after sometime.",
    ),  # NOSONAR
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
    (
        {"ip": "5844.2204.2191.2471"},
        "negative",
        {},
        200,
        "Invalid IP address: '5844.2204.2191.2471'",
    ),  # NOSONAR
]

get_ip_reputation_score_data = [
    ("unknown", (0, "Unknown")),
    ("", (0, "Unknown")),
    ("benign", (1, "Good")),
    ("malicious", (3, "Bad")),
    ("dummy", (0, "Unknown")),
]

valid_ip_context_data = {
    "ip": "71.6.135.131",
    "noise": True,
    "riot": False,
    "classification": "benign",
    "name": "Shodan.io",
    "link": "https://viz.greynoise.io/ip/71.6.135.131",
    "last_seen": "2021-05-10",
    "message": "Success",
}

valid_ip_context_data_response = [
    {
        "IP": "[71.6.135.131](https://viz.greynoise.io/ip/71.6.135.131)",  # NOSONAR
        "Noise": True,
        "Riot": False,
        "Classification": "benign",
        "Last Seen": "2021-05-10",
        "Name": "Shodan.io",
        "Link": "https://viz.greynoise.io/ip/71.6.135.131",
        "Message": "Success",
    }
]

get_ip_context_data_data = [([valid_ip_context_data], valid_ip_context_data_response)]
