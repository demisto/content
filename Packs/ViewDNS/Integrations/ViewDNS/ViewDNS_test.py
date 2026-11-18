"""Unit tests for the ViewDNS integration.

The fixtures in test_data are built from the response formats documented at https://viewdns.info/api/documentation/.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from CommonServerPython import DemistoException, EntryType

import ViewDNS
from ViewDNS import Client

BASE_URL = "https://api.viewdns.info"
API_KEY = "0123456789abcdef0123456789abcdef01234567"
RELIABILITY = "C - Fairly reliable"


def load_json(name: str) -> dict[str, Any]:
    return json.loads((Path(__file__).parent / "test_data" / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, api_key=API_KEY, verify=True, proxy=False)


def query_of(requests_mock, index: int = -1) -> dict[str, list[str]]:
    return requests_mock.request_history[index].qs


""" CLIENT """


def test_request_sends_api_key_and_json_output(client, requests_mock):
    """
    Given: a client
    When: any API call is made
    Then: the API key and output=json are sent as query parameters and unset parameters are omitted
    """
    requests_mock.get(f"{BASE_URL}/reverseip/", json=load_json("reverse_ip"))

    client.reverse_ip("example.com")

    query = query_of(requests_mock)
    assert query["apikey"] == [API_KEY]
    assert query["output"] == ["json"]
    assert query["host"] == ["example.com"]
    assert "page" not in query


@pytest.mark.parametrize(
    "status_code, fixture, expected",
    [
        (400, "error_400", "invalid input. ViewDNS message: Invalid domain or IP specified."),
        (401, "error_401", "authorization error - the API key is invalid."),
        (403, "error_403", "does not have access to this tool"),
        (429, "error_429", "the query limit was reached"),
    ],
)
def test_http_errors_are_mapped_to_clear_messages(client, requests_mock, status_code, fixture, expected):
    """
    Given: a ViewDNS error response (bad input, bad key, tool not allowed, out of queries)
    When: an API call is made
    Then: a DemistoException with a clear message is raised and the request is not repeated
    """
    requests_mock.get(f"{BASE_URL}/whois/v2/", status_code=status_code, json=load_json(fixture))

    with pytest.raises(DemistoException, match=expected):
        client.whois("example.com")

    assert requests_mock.call_count == 1


def test_error_message_never_contains_api_key(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/whois/v2/", status_code=401, json=load_json("error_401"))

    with pytest.raises(DemistoException) as error:
        client.whois("example.com")

    assert API_KEY not in str(error.value)


def test_server_error_without_json_body(client, requests_mock):
    """
    Given: a 5xx response with a non-JSON body
    When: an API call is made
    Then: a DemistoException is raised
    """
    requests_mock.get(f"{BASE_URL}/portscan/", status_code=503, text="Service Unavailable")

    with pytest.raises(DemistoException):
        client.port_scan("example.com")


def test_request_is_configured_to_retry_on_server_errors_only(client, mocker):
    """
    Given: a client
    When: an API call is made
    Then: retries with backoff are requested for 5xx responses and not for 429 (quota exhausted)
    """
    response = mocker.Mock(status_code=200)
    response.json.return_value = load_json("port_scan")
    http_request = mocker.patch.object(Client, "_http_request", return_value=response)

    client.port_scan("example.com")

    kwargs = http_request.call_args.kwargs
    assert kwargs["retries"] == 3
    assert kwargs["backoff_factor"] > 0
    assert kwargs["status_list_to_retry"] == [500, 502, 503, 504]
    assert 429 not in kwargs["status_list_to_retry"]


@pytest.mark.parametrize("text", ["<html>not json</html>", "[]"])
def test_unexpected_success_body(client, requests_mock, text):
    requests_mock.get(f"{BASE_URL}/traceroute/", text=text)

    with pytest.raises(DemistoException, match="ViewDNS: the API returned"):
        client.traceroute("example.com")


def test_missing_response_key_is_treated_as_empty(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/portscan/", json={"query": {"tool": "portscan_PRO"}, "response": None})

    assert client.port_scan("example.com")["response"] == {}


def test_error_in_successful_response_is_raised(client, requests_mock):
    """
    Given: an HTTP 200 response whose body carries an error message
    When: an API call is made
    Then: the error is raised with the API message
    """
    requests_mock.get(f"{BASE_URL}/reverseip/", json=load_json("reverse_ip_error"))

    with pytest.raises(DemistoException, match="could not find the IP address"):
        client.reverse_ip("nonexistent.example")


@pytest.mark.parametrize(
    "status_code, message, expected",
    [
        (500, "", "ViewDNS: the API returned an error (HTTP 500)."),
        (500, "boom", "ViewDNS: the API returned an error (HTTP 500). ViewDNS message: boom"),
    ],
)
def test_build_error_message_for_other_statuses(status_code, message, expected):
    assert ViewDNS.build_error_message(status_code, message) == expected


@pytest.mark.parametrize(
    "body, expected",
    [
        ({"success": False, "error": {"code": 400, "message": "bad"}}, "bad"),
        ({"error": "plain"}, "plain"),
        ({"success": False}, ""),
        (["unexpected"], ""),
    ],
)
def test_extract_error_message(mocker, body, expected):
    response = mocker.Mock()
    response.json.return_value = body

    assert ViewDNS.extract_error_message(response) == expected


""" ARGUMENT HANDLING """


@pytest.mark.parametrize("args", [{"host": "example.com", "page": "0"}, {"host": "example.com", "limit": "-5"}])
def test_non_positive_page_and_limit_are_rejected(client, args):
    with pytest.raises(DemistoException, match="must be a positive number"):
        ViewDNS.reverse_ip_command(client, args)


@pytest.mark.parametrize(
    "command, arg_name",
    [
        (ViewDNS.reverse_ip_command, "host"),
        (ViewDNS.reverse_whois_command, "query"),
        (ViewDNS.reverse_ns_command, "nameserver"),
        (ViewDNS.reverse_mx_command, "mail_server"),
        (ViewDNS.ip_history_command, "domain"),
        (ViewDNS.dns_record_command, "domain"),
        (ViewDNS.whois_command, "domain"),
        (ViewDNS.port_scan_command, "host"),
        (ViewDNS.ping_command, "host"),
        (ViewDNS.traceroute_command, "host"),
    ],
)
def test_missing_required_argument(client, requests_mock, command, arg_name):
    """
    Given: a command called without its required argument
    When: the command runs
    Then: an error is raised before any API query is consumed
    """
    with pytest.raises(DemistoException, match=f"The '{arg_name}' argument is required."):
        command(client, {arg_name: "  "})

    assert requests_mock.call_count == 0


""" TEST MODULE AND ACCOUNT """


def test_test_module_success(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/account/", json=load_json("account_balance"))

    assert ViewDNS.test_module(client) == "ok"
    assert query_of(requests_mock)["action"] == ["balance"]


@pytest.mark.parametrize("status_code, fixture", [(200, "account_invalid_key"), (401, "error_401")])
def test_test_module_invalid_key(client, requests_mock, status_code, fixture):
    """
    Given: an invalid API key, reported either in a 200 body (Account API) or as HTTP 401
    When: the test button is clicked
    Then: an authorization error message is returned
    """
    requests_mock.get(f"{BASE_URL}/account/", status_code=status_code, json=load_json(fixture))

    assert ViewDNS.test_module(client).startswith("Authorization Error")


def test_test_module_other_error_is_raised(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/account/", status_code=503, text="down")

    with pytest.raises(DemistoException):
        ViewDNS.test_module(client)


def test_account_balance_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/account/", json=load_json("account_balance"))

    result = ViewDNS.account_balance_command(client, {})

    assert result.outputs_prefix == "ViewDNS.Account"
    assert result.outputs == {
        "Plan": "monthly",
        "MonthlyLimit": 10000,
        "MonthlyUsage": 3197,
        "MonthlyRemaining": 6803,
        "PrepaidBalance": 2000,
    }
    assert "ViewDNS Account Balance" in result.readable_output


def test_account_balance_command_trial_plan(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/account/", json=load_json("account_balance_trial"))

    result = ViewDNS.account_balance_command(client, {})

    assert result.outputs["Plan"] == "trial"
    assert result.outputs["MonthlyRemaining"] == 238
    assert result.outputs["PrepaidBalance"] == 0


""" LOOKUP COMMANDS """


def test_reverse_ip_command(client, requests_mock):
    """
    Given: a host with five co-hosted domains and a limit of two
    When: viewdns-reverse-ip runs
    Then: two domains are returned, the full count is kept and the page is passed to the API
    """
    requests_mock.get(f"{BASE_URL}/reverseip/", json=load_json("reverse_ip"))

    result = ViewDNS.reverse_ip_command(client, {"host": "example.com", "page": "2", "limit": "2"})

    assert query_of(requests_mock)["page"] == ["2"]
    assert result.outputs_prefix == "ViewDNS.ReverseIP"
    assert result.outputs_key_field == "Host"
    assert result.outputs == {
        "Host": "example.com",
        "DomainCount": 5,
        "Page": 2,
        "Domains": [
            {"Name": "atlabs.dev", "LastResolved": "2024-09-28"},
            {"Name": "example.com", "LastResolved": "2024-10-02"},
        ],
    }
    assert "showing 2 of 5, page 2" in result.readable_output
    assert result.raw_response == load_json("reverse_ip")


def test_reverse_ip_command_no_results(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/reverseip/", json=load_json("reverse_ip_empty"))

    result = ViewDNS.reverse_ip_command(client, {"host": "192.0.2.1"})

    assert "No results found" in result.readable_output
    assert result.outputs == {"Host": "192.0.2.1", "DomainCount": 0, "Page": 1, "Domains": []}


def test_reverse_whois_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/reversewhois/", json=load_json("reverse_whois"))

    result = ViewDNS.reverse_whois_command(client, {"query": "domain@example.com", "limit": "3"})

    assert query_of(requests_mock)["q"] == ["domain@example.com"]
    assert result.outputs_prefix == "ViewDNS.ReverseWhois"
    assert result.outputs_key_field == "Query"
    assert result.outputs["ResultCount"] == 4
    assert result.outputs["TotalPages"] == 1
    assert result.outputs["CurrentPage"] == 1
    assert len(result.outputs["Matches"]) == 3
    assert result.outputs["Matches"][0] == {
        "Domain": "atheismfacts.org",
        "CreatedDate": "2012-08-03",
        "Registrar": "NAME.COM, LLC",
    }
    assert "showing 3 of 4" in result.readable_output


def test_reverse_whois_command_no_results(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/reversewhois/", json=load_json("reverse_whois_empty"))

    result = ViewDNS.reverse_whois_command(client, {"query": "nobody@nowhere.example"})

    assert "No results found" in result.readable_output
    assert result.outputs["ResultCount"] == 0
    assert result.outputs["Matches"] == []


def test_reverse_whois_command_rejects_demo_data(client, requests_mock):
    """
    Given: a free API key, for which the API returns demonstration data with HTTP 200
    When: viewdns-reverse-whois runs
    Then: an error is raised instead of presenting the demonstration domains as findings
    """
    requests_mock.get(f"{BASE_URL}/reversewhois/", json=load_json("reverse_whois_demo"))

    with pytest.raises(DemistoException, match="paid API keys only"):
        ViewDNS.reverse_whois_command(client, {"query": "domain@example.com"})


def test_reverse_ns_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/reversens/", json=load_json("reverse_ns"))

    result = ViewDNS.reverse_ns_command(client, {"nameserver": "ns1.example.com", "limit": "2"})

    assert query_of(requests_mock)["ns"] == ["ns1.example.com"]
    assert result.outputs_prefix == "ViewDNS.ReverseNS"
    assert result.outputs_key_field == "Nameserver"
    assert result.outputs == {
        "Nameserver": "ns1.example.com",
        "DomainCount": 2217,
        "TotalPages": 1,
        "CurrentPage": 1,
        "Domains": ["123riff.com", "2cthefacebook.com"],
    }


def test_reverse_mx_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/reversemx/", json=load_json("reverse_mx"))

    result = ViewDNS.reverse_mx_command(client, {"mail_server": "mail.example.com"})

    assert query_of(requests_mock)["mx"] == ["mail.example.com"]
    assert result.outputs_prefix == "ViewDNS.ReverseMX"
    assert result.outputs_key_field == "MailServer"
    assert result.outputs["DomainCount"] == 981
    assert result.outputs["Domains"] == ["090803.com", "1sthealthcare.net", "academyhill.org"]
    assert "| academyhill.org |" in result.readable_output


@pytest.mark.parametrize(
    "command, path, args, fixture",
    [
        (ViewDNS.reverse_ns_command, "reversens", {"nameserver": "ns1.unused.example"}, "reverse_ns_empty"),
        (ViewDNS.reverse_mx_command, "reversemx", {"mail_server": "mx.unused.example"}, "reverse_mx_empty"),
    ],
)
def test_reverse_server_commands_no_results(client, requests_mock, command, path, args, fixture):
    requests_mock.get(f"{BASE_URL}/{path}/", json=load_json(fixture))

    result = command(client, args)

    assert "No results found" in result.readable_output
    assert result.outputs["DomainCount"] == 0
    assert result.outputs["Domains"] == []


def test_ip_history_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/iphistory/", json=load_json("ip_history"))

    result = ViewDNS.ip_history_command(client, {"domain": "example.com", "limit": "1"})

    assert result.outputs_prefix == "ViewDNS.IPHistory"
    assert result.outputs_key_field == "Domain"
    assert result.outputs == {
        "Domain": "example.com",
        "RecordCount": 4,
        "Records": [{"IP": "172.64.145.59", "Location": "Unknown", "Owner": "Cloudflare, Inc", "LastSeen": "2024-09-20"}],
    }
    assert "showing 1 of 4" in result.readable_output


def test_ip_history_command_no_results(client, requests_mock):
    """
    Given: a domain ViewDNS has no history for, which the API reports as an error string in a 200 response
    When: viewdns-ip-history runs
    Then: "No results found" is returned rather than an error
    """
    requests_mock.get(f"{BASE_URL}/iphistory/", json=load_json("ip_history_empty"))

    result = ViewDNS.ip_history_command(client, {"domain": "unknown-domain.example"})

    assert "No results found" in result.readable_output
    assert result.outputs == {"Domain": "unknown-domain.example", "RecordCount": 0, "Records": []}


def test_ip_history_command_invalid_input(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/iphistory/", json=load_json("ip_history_error"))

    with pytest.raises(DemistoException, match="Please provide a domain name not an IP address."):
        ViewDNS.ip_history_command(client, {"domain": "198.51.100.1"})


def test_dns_record_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/dnsrecord/", json=load_json("dns_record"))

    result = ViewDNS.dns_record_command(client, {"domain": "example.com"})

    assert query_of(requests_mock)["recordtype"] == ["any"]
    assert result.outputs_prefix == "ViewDNS.DNSRecord"
    assert result.outputs_key_field == ["Domain", "RecordType"]
    assert result.outputs["RecordType"] == "ANY"
    records = result.outputs["Records"]
    assert len(records) == 5
    assert records[2] == {"Name": "example.com.", "TTL": 300, "Class": "IN", "Type": "A", "Data": "172.64.145.59"}
    assert records[4]["Priority"] == 10
    assert "Priority" not in records[0]


def test_dns_record_command_no_results(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/dnsrecord/", json=load_json("dns_record_empty"))

    result = ViewDNS.dns_record_command(client, {"domain": "example.com", "record_type": "caa"})

    assert query_of(requests_mock)["recordtype"] == ["caa"]
    assert result.outputs == {"Domain": "example.com", "RecordType": "CAA", "Records": []}
    assert "No results found for CAA records of example.com" in result.readable_output


def test_whois_command_domain(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/whois/v2/", json=load_json("whois_domain"))

    result = ViewDNS.whois_command(client, {"domain": "example.com"})

    assert result.outputs_prefix == "ViewDNS.Whois"
    assert result.outputs_key_field == "DomainName"
    outputs = result.outputs
    assert outputs["DomainName"] == "example.com"
    assert outputs["RegistrarName"] == "Example Registrar, LLC"
    assert outputs["RegistrarIANAID"] == "886"
    assert outputs["CreatedDate"] == "1994-07-01T04:00:00Z"
    assert outputs["ExpiresDate"] == "2031-01-07T13:34:24Z"
    assert outputs["AbuseEmail"] == "abuse@example.net"
    assert outputs["Registrant"]["Email"] == "domains@example.com"
    assert outputs["Registrant"]["Phone"] == "+1.5555550100"
    assert "Fax" not in outputs["Registrant"]
    assert outputs["NameServers"] == ["lee.ns.cloudflare.com", "sarah.ns.cloudflare.com"]
    assert outputs["Status"] == ["clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"]
    assert outputs["RawText"].startswith("Domain Name: EXAMPLE.COM")
    assert outputs["RawText"].endswith("Example Organization, Inc. & Co")
    assert "RawText" not in result.readable_output
    assert "Example Registrar, LLC" in result.readable_output


@pytest.mark.parametrize(
    "status, expected",
    [
        ("clientHold https://icann.org/epp#clientHold", ["clientHold"]),
        ("delete prohibited\nrenew prohibited", ["delete prohibited", "renew prohibited"]),
        ("Registered until expiry date.", ["Registered until expiry date."]),
    ],
)
def test_domain_whois_status_formats(status, expected):
    """
    Given: WHOIS status values in the formats used by different registries
    When: the record is parsed
    Then: each status is kept whole, without the ICANN reference URL
    """
    response = {"domainName": "example.info", "registrarName": "Registrar", "registryData": {"status": status}}

    assert ViewDNS.parse_domain_whois("example.info", response)["Status"] == expected


def test_whois_command_ip(client, requests_mock):
    """
    Given: an IP address
    When: viewdns-whois runs
    Then: the network registration is returned under ViewDNS.IPWhois, without the empty values of the API response
    """
    requests_mock.get(f"{BASE_URL}/whois/v2/", json=load_json("whois_ip"))

    result = ViewDNS.whois_command(client, {"domain": "198.51.100.1"})

    assert result.outputs_prefix == "ViewDNS.IPWhois"
    assert result.outputs_key_field == "IP"
    outputs = result.outputs
    assert outputs["IP"] == "198.51.100.1"
    assert outputs["Registry"] == "ARIN"
    assert outputs["Owner"] == "Example Networks LLC (EXNET)"
    assert outputs["CIDR"] == "198.51.100.0/24"
    assert outputs["NetRange"] == "198.51.100.0 - 198.51.100.255"
    assert "ASN" not in outputs
    assert "Status" not in outputs
    assert outputs["Abuse"] == {"Name": "Abuse", "Phone": "+1-555-555-0100", "Email": "abuse@example.net"}
    assert outputs["Tech"]["Email"] == "noc@example.net"


def test_whois_command_no_results(client, requests_mock):
    """
    Given: an unregistered domain, for which the API returns a record with empty fields and only the raw registry text
    When: viewdns-whois runs
    Then: "No results found" is returned, nothing is written to context and the raw response is kept
    """
    requests_mock.get(f"{BASE_URL}/whois/v2/", json=load_json("whois_domain_empty"))

    result = ViewDNS.whois_command(client, {"domain": "unregistered-domain-example.com"})

    assert "No results found" in result.readable_output
    assert result.outputs is None
    assert "No match for" in result.raw_response["response"]["registryData"]["rawText"]


def test_port_scan_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/portscan/", json=load_json("port_scan"))

    result = ViewDNS.port_scan_command(client, {"host": "example.com"})

    assert result.outputs_prefix == "ViewDNS.PortScan"
    assert result.outputs_key_field == "Host"
    assert result.outputs["OpenPorts"] == [80, 443]
    assert result.outputs["Ports"][0] == {"Number": 21, "Service": "FTP", "Status": "closed"}
    assert len(result.outputs["Ports"]) == 5
    assert "(2 open)" in result.readable_output


def test_ping_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/ping/v2/", json=load_json("ping"))

    result = ViewDNS.ping_command(client, {"host": "example.com"})

    assert result.outputs_prefix == "ViewDNS.Ping"
    assert result.outputs["Host"] == "example.com"
    results = result.outputs["Results"]
    assert len(results) == 3
    assert results[0] == {
        "Region": "Asia",
        "Location": "Hong Kong, China",
        "IPAddress": "23.215.0.138",
        "MinRTT": 207.854,
        "MaxRTT": 208.289,
        "AvgRTT": 208.123,
        "PacketLoss": "25%",
    }
    assert results[2]["Region"] == "South America"


def test_traceroute_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/traceroute/", json=load_json("traceroute"))

    result = ViewDNS.traceroute_command(client, {"host": "example.com"})

    assert query_of(requests_mock)["domain"] == ["example.com"]
    assert result.outputs_prefix == "ViewDNS.Traceroute"
    assert len(result.outputs["Hops"]) == 4
    assert result.outputs["Hops"][2] == {
        "Number": 3,
        "Hostname": "air-mdsn-usshc.airstreamcomm.net",
        "IP": "64.33.146.250",
        "RTT": 3.513,
    }


@pytest.mark.parametrize(
    "command, path",
    [
        (ViewDNS.port_scan_command, "portscan"),
        (ViewDNS.ping_command, "ping/v2"),
        (ViewDNS.traceroute_command, "traceroute"),
    ],
)
def test_active_commands_no_results(client, requests_mock, command, path):
    requests_mock.get(f"{BASE_URL}/{path}/", json={"query": {}, "response": {}})

    result = command(client, {"host": "example.com"})

    assert "No results found" in result.readable_output


@pytest.mark.parametrize(
    "command, path",
    [
        (ViewDNS.port_scan_command, "portscan"),
        (ViewDNS.ping_command, "ping/v2"),
        (ViewDNS.traceroute_command, "traceroute"),
    ],
)
def test_active_commands_invalid_host(client, requests_mock, command, path):
    requests_mock.get(f"{BASE_URL}/{path}/", status_code=400, json=load_json("error_400"))

    with pytest.raises(DemistoException, match="invalid input"):
        command(client, {"host": "not a host"})


""" REPUTATION COMMANDS """


@pytest.mark.parametrize(
    "command, args",
    [(ViewDNS.domain_command, {"domain": "example.com"}), (ViewDNS.ip_command, {"ip": "198.51.100.1"})],
)
def test_reputation_commands_disabled(client, requests_mock, command, args):
    """
    Given: reputation commands are disabled in the instance settings (the default)
    When: a reputation command runs
    Then: a clear message is returned and no API query is consumed
    """
    results = command(client, args, False, RELIABILITY)

    assert len(results) == 1
    assert "reputation commands are disabled" in results[0].readable_output
    assert results[0].indicator is None
    assert requests_mock.call_count == 0


def test_domain_command(client, requests_mock):
    """
    Given: reputation commands are enabled
    When: the domain command runs
    Then: a Common.Domain indicator with WHOIS data and an Unknown DBot score is returned, with the IP history in context
    """
    requests_mock.get(f"{BASE_URL}/whois/v2/", json=load_json("whois_domain"))
    requests_mock.get(f"{BASE_URL}/iphistory/", json=load_json("ip_history"))

    results = ViewDNS.domain_command(client, {"domain": "example.com"}, True, RELIABILITY)

    assert len(results) == 1
    context = results[0].to_context()["EntryContext"]
    domain = context["Domain(val.Name && val.Name == obj.Name)"][0]
    assert domain["Name"] == "example.com"
    assert domain["Registrar"]["Name"] == "Example Registrar, LLC"
    assert domain["Registrant"]["Email"] == "domains@example.com"
    assert domain["CreationDate"] == "1994-07-01T04:00:00Z"
    assert domain["NameServers"] == ["lee.ns.cloudflare.com", "sarah.ns.cloudflare.com"]

    score = next(value for key, value in context.items() if key.startswith("DBotScore"))[0]
    assert score == {
        "Indicator": "example.com",
        "Type": "domain",
        "Vendor": "ViewDNS",
        "Score": 0,
        "Reliability": RELIABILITY,
    }

    outputs = results[0].outputs
    assert outputs["Name"] == "example.com"
    assert outputs["IPHistoryCount"] == 4
    assert outputs["IPHistory"][0]["IP"] == "172.64.145.59"
    assert "RawText" not in outputs["Whois"]
    assert "IP History for example.com" in results[0].readable_output


def test_domain_command_without_data(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/whois/v2/", json=load_json("whois_domain_empty"))
    requests_mock.get(f"{BASE_URL}/iphistory/", json=load_json("ip_history_empty"))

    results = ViewDNS.domain_command(client, {"domain": "unknown-domain.example"}, True, RELIABILITY)

    assert "No results found" in results[0].readable_output
    assert results[0].outputs["IPHistoryCount"] == 0
    assert results[0].indicator.dbot_score.score == 0


def test_ip_command(client, requests_mock):
    requests_mock.get(f"{BASE_URL}/whois/v2/", json=load_json("whois_ip"))
    requests_mock.get(f"{BASE_URL}/reverseip/", json=load_json("reverse_ip"))

    results = ViewDNS.ip_command(client, {"ip": "198.51.100.1"}, True, RELIABILITY)

    assert len(results) == 1
    context = results[0].to_context()["EntryContext"]
    ip = context["IP(val.Address && val.Address == obj.Address)"][0]
    assert ip["Address"] == "198.51.100.1"
    assert ip["ASOwner"] == "Example Networks LLC (EXNET)"
    assert ip["Geo"]["Country"] == "US"
    assert ip["Registrar"]["Abuse"]["Email"] == "abuse@example.net"
    assert ip["Registrar"]["Abuse"]["Network"] == "198.51.100.0/24"

    score = next(value for key, value in context.items() if key.startswith("DBotScore"))[0]
    assert score["Score"] == 0
    assert score["Type"] == "ip"
    assert score["Vendor"] == "ViewDNS"

    outputs = results[0].outputs
    assert outputs["Address"] == "198.51.100.1"
    assert outputs["HostedDomainCount"] == 5
    assert len(outputs["HostedDomains"]) == 5
    assert outputs["Whois"]["Registry"] == "ARIN"


def test_reputation_command_continues_after_failed_indicator(client, requests_mock):
    """
    Given: two IP addresses, the first of which is rejected by the API
    When: the ip command runs
    Then: a warning is returned for the first and the second is still enriched
    """
    requests_mock.get(f"{BASE_URL}/whois/v2/?domain=bad", status_code=400, json=load_json("error_400"))
    requests_mock.get(f"{BASE_URL}/whois/v2/?domain=198.51.100.1", json=load_json("whois_ip"))
    requests_mock.get(f"{BASE_URL}/reverseip/", json=load_json("reverse_ip_empty"))

    results = ViewDNS.ip_command(client, {"ip": "bad,198.51.100.1"}, True, RELIABILITY)

    assert len(results) == 2
    assert results[0].entry_type == EntryType.WARNING
    assert "could not enrich bad" in results[0].readable_output
    assert results[1].outputs["Address"] == "198.51.100.1"
    assert results[1].outputs["HostedDomainCount"] == 0


def test_reputation_command_requires_indicator(client):
    with pytest.raises(DemistoException, match="The 'domain' argument is required."):
        ViewDNS.domain_command(client, {}, True, RELIABILITY)


""" MAIN """


def run_main(mocker, command: str, args: dict[str, Any], params: dict[str, Any] | None = None):
    default_params = {"url": BASE_URL, "credentials": {"password": API_KEY}, "integrationReliability": RELIABILITY}
    mocker.patch.object(ViewDNS.demisto, "params", return_value=default_params if params is None else params)
    mocker.patch.object(ViewDNS.demisto, "args", return_value=args)
    mocker.patch.object(ViewDNS.demisto, "command", return_value=command)
    results = mocker.patch.object(ViewDNS, "return_results")
    error = mocker.patch.object(ViewDNS, "return_error")
    ViewDNS.main()
    return results, error


def test_main_dispatches_command(mocker, requests_mock):
    requests_mock.get(f"{BASE_URL}/reverseip/", json=load_json("reverse_ip"))

    results, error = run_main(mocker, "viewdns-reverse-ip", {"host": "example.com"})

    error.assert_not_called()
    assert results.call_args.args[0].outputs["DomainCount"] == 5


def test_main_test_module(mocker, requests_mock):
    requests_mock.get(f"{BASE_URL}/account/", json=load_json("account_balance"))

    results, error = run_main(mocker, "test-module", {})

    error.assert_not_called()
    results.assert_called_once_with("ok")


@pytest.mark.parametrize("command, args", [("domain", {"domain": "example.com"}), ("ip", {"ip": "198.51.100.1"})])
def test_main_reputation_disabled_by_default(mocker, requests_mock, command, args):
    results, error = run_main(mocker, command, args)

    error.assert_not_called()
    assert "reputation commands are disabled" in results.call_args.args[0][0].readable_output
    assert requests_mock.call_count == 0


def test_main_reputation_enabled(mocker, requests_mock):
    requests_mock.get(f"{BASE_URL}/whois/v2/", json=load_json("whois_ip"))
    requests_mock.get(f"{BASE_URL}/reverseip/", json=load_json("reverse_ip"))
    params = {"credentials": {"password": API_KEY}, "enable_reputation": True, "integrationReliability": "B - Usually reliable"}

    results, error = run_main(mocker, "ip", {"ip": "198.51.100.1"}, params)

    error.assert_not_called()
    assert results.call_args.args[0][0].indicator.dbot_score.reliability == "B - Usually reliable"


def test_main_reports_errors_without_api_key(mocker, requests_mock):
    """
    Given: a request failure whose message contains the request URL, including the API key
    When: main handles the error
    Then: the API key is removed from the message shown to the user and from the debug traceback
    """
    mocker.patch.object(Client, "_http_request", side_effect=DemistoException(f"failed: {BASE_URL}/whois/v2/?apikey={API_KEY}"))
    debug = mocker.patch.object(ViewDNS.demisto, "debug")

    _, error = run_main(mocker, "viewdns-whois", {"domain": "example.com"})

    message = error.call_args.args[0]
    assert "Failed to execute viewdns-whois command." in message
    assert API_KEY not in message
    assert "<api-key>" in message
    assert isinstance(error.call_args.kwargs["error"], DemistoException)
    traceback_text = debug.call_args.args[0]
    assert "Traceback" in traceback_text
    assert API_KEY not in traceback_text
    assert "<api-key>" in traceback_text


@pytest.mark.parametrize(
    "command, params, expected",
    [
        ("viewdns-whois", {"credentials": {}}, "The API key is required."),
        (
            "viewdns-whois",
            {"credentials": {"password": API_KEY}, "integrationReliability": "Z - Unknown"},
            "Invalid source reliability",
        ),
        ("viewdns-unknown", {"credentials": {"password": API_KEY}}, "is not implemented"),
    ],
)
def test_main_configuration_errors(mocker, command, params, expected):
    _, error = run_main(mocker, command, {"domain": "example.com"}, params)

    assert expected in error.call_args.args[0]
