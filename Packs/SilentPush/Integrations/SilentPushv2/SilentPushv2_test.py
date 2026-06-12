import uuid
import json
from requests import Response
import pytest

from SilentPushv2 import (
    Client,
    CommandResults,
    get_nameserver_reputation_command,
    get_subnet_reputation_command,
    get_asns_for_domain_command,
    list_domain_information_command,
    list_ip4_information_command,
    list_ip6_information_command,
    get_ipv4_reputation_command,
    get_enrichment_data_command,
    bulk_enrich_command,
    get_domain_certificates_command,
    live_url_scan_command,
    search_scan_data_command,
    reverse_padns_lookup_command,
    forward_padns_lookup_command,
    ip_diversity_lookup_command,
    ip_diversity_patterns_command,
    multi_conditional_padns_lookup_command,
    search_domains_command,
    density_lookup_command,
    add_feed_command,
    add_indicators_command,
    add_indicators_tags_command,
    get_data_exports_command,
    run_threat_check_command,
    add_feed_tags_command,
    whois_command,
    retry_job_command,
)
from CommonServerPython import DemistoException, EntryType, tableToMarkdown


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client(mocker):
    client = mocker.Mock(spec=Client)
    client.response_has_job.return_value = False
    client.get_markdown.return_value = "Mocked Readable Output"
    mocker.patch("SilentPushv2.tableToMarkdown", return_value="Mocked Markdown Table")
    return client


def test_get_nameserver_reputation_command(mock_client, mocker):
    args = {"nameserver": "example.com", "explain": "true", "limit": 10}
    mock_response = [{"ns_server": "example.com", "reputation": "good", "details": "No issues found", "date": "20240101"}]
    mock_client.get_reputation.return_value = ("Mocked Markdown Table", mock_response)
    result = get_nameserver_reputation_command(mock_client, args)
    mock_client.get_reputation.assert_called_once()
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.NameserverReputation"
    assert result.outputs_key_field == "ns_server"
    assert result.outputs["nameserver"] == "example.com"
    assert result.outputs["reputation_data"] == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_get_subnet_reputation_command(mock_client, mocker):
    args = {"subnet": "192.168.1.0/24", "explain": "true", "limit": "5"}
    mock_response = [{"subnet": "192.168.1.0/24", "reputation": "suspicious", "details": "Found in blacklist"}]
    mock_client.get_reputation.return_value = ("Mocked Markdown Table", mock_response)
    result = get_subnet_reputation_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.SubnetReputation"
    assert result.outputs_key_field == "subnet"
    assert result.outputs["subnet"] == "192.168.1.0/24"
    assert result.outputs["reputation_history"] == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_get_ipv4_reputation_command(mock_client, mocker):
    args = {"ipv4": "1.1.1.1"}
    mock_response = [
        {
            "date": 20260526,
            "ip": "1.1.1.1",
            "ip_reputation": 0,
            "ip_reputation_explain": {"ip_density": 23, "names_num_listed": 0},
        }
    ]
    mock_client.get_reputation.return_value = ("Mocked Markdown Table", mock_response)
    result = get_ipv4_reputation_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IPv4Reputation"
    assert result.outputs_key_field == "ip"
    assert result.outputs == {"IPv4": args.get("ipv4"), "reputation_history": mock_response}
    assert result.outputs["reputation_history"] == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_get_asns_for_domain_command(mock_client, mocker):
    args = {"domain": "example.com"}
    mock_response = {
        "response": {"records": [{"domain_asns": {"12345": "Example ASN Description", "67890": "Another ASN Description"}}]}
    }
    mock_client._http_request.return_value = mock_response
    result = get_asns_for_domain_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.DomainASNs"
    assert result.outputs_key_field == "domain"
    assert result.outputs["domain"] == "example.com"
    assert result.outputs["asns"] == [
        {"ASN": "12345", "Description": "Example ASN Description"},
        {"ASN": "67890", "Description": "Another ASN Description"},
    ]
    assert result.readable_output == "Mocked Markdown Table"


def test_list_domain_information_command(mock_client, mocker):
    args = {"domains": "example.com,example.org"}
    mock_response = [
        {
            "domain_string_frequency_probability": {},
            "domain_urls": {},
            "domaininfo": {},
            "host_flags": [{}],
            "ip_diversity": {},
            "is_private_suffix": False,
            "listing_score": 0,
            "listing_score_explain": {},
            "listing_score_feeds_explain": [],
            "ns_reputation": {},
            "nschanges": {"results_summary": {}},
            "private_suffix_info": {},
            "sp_risk_score": 36,
            "sp_risk_score_explain": {"sp_risk_score_decider": "ns_reputation_score"},
        }
    ]
    mock_client.get_bulk_info.return_value = (mock_response, "Mocked Markdown Table")
    result = list_domain_information_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Domain"
    assert result.outputs_key_field == "domain"
    assert result.outputs == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_list_ip4_information_command(mock_client, mocker):
    args = {"ips": "1.1.1.1,2.2.2.2"}
    mock_response = [
        {
            "asn": 11111,
            "asn_allocation_age": 1111,
            "asn_allocation_date": 20010101,
            "asn_rank": 0,
            "sp_risk_score": 0,
            "sp_risk_score_explain": {},
            "subnet": "1.1.1.0/24",
        }
    ]
    mock_client.get_bulk_info.return_value = (mock_response, "Mocked Markdown Table")
    result = list_ip4_information_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IP4"
    assert result.outputs_key_field == "ip"
    assert result.outputs == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_list_ip6_information_command(mock_client, mocker):
    args = {"ips": "2001:0db8:85a3:0000:0000:8a2e:0370:7334,2001:0db8:85a3:0000:0000:8a2e:0370:7335"}
    mock_response = [
        {
            "asn": 11111,
            "asn_allocation_age": 1111,
            "asn_allocation_date": 20010101,
            "asn_rank": 0,
            "sp_risk_score": 0,
            "sp_risk_score_explain": {},
            "subnet": "2001:db8:abcd:0012::/64",
        }
    ]
    mock_client.get_bulk_info.return_value = (mock_response, "Mocked Markdown Table")
    result = list_ip6_information_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IP6"
    assert result.outputs_key_field == "ip"
    assert result.outputs == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_get_enrichment_data_command(mock_client, mocker):
    args = {"resource": "ipv4", "value": "192.168.1.1", "explain": "true", "scan_data": "false"}
    mock_response = {"value": "192.168.1.1", "reputation": "good", "details": "No malicious activity detected"}
    mock_client.get_enrichment_data.return_value = mock_response
    result = get_enrichment_data_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Enrichment"
    assert result.outputs_key_field == "value"
    assert result.outputs["value"] == "192.168.1.1"
    assert result.outputs["reputation"] == "good"
    assert result.readable_output == "Mocked Markdown Table"


def test_get_enrichment_data_command_invalid_resource(mock_client):
    args = {"resource": "invalid_resource", "value": "192.168.1.1"}
    with pytest.raises(ValueError, match="Invalid input: invalid_resource. Allowed values are"):
        get_enrichment_data_command(mock_client, args)


def test_bulk_enrich_command(mock_client, mocker):
    args = {"resource": "ipv4", "value": "1.1.1.1,2.2.2.2"}
    mock_response = [
        {
            "domain_string_frequency_probability": {},
            "domain_urls": {"results_summary": {}},
            "domaininfo": {},
            "host_flags": [{}],
            "ip_diversity": {},
            "is_private_suffix": False,
            "listing_score": 0,
            "listing_score_explain": {},
            "listing_score_feeds_explain": [],
            "ns_reputation": {"ns_srv_reputation": [{}]},
            "nschanges": {"results_summary": {}},
            "private_suffix_info": {},
            "sp_risk_score": 36,
            "sp_risk_score_explain": {"sp_risk_score_decider": "ns_reputation_score"},
        },
        {
            "domain_string_frequency_probability": {},
            "domain_urls": {"results_summary": {}},
            "domaininfo": {},
            "host_flags": [{}],
            "ip_diversity": {},
            "is_private_suffix": False,
            "listing_score": 0,
            "listing_score_explain": {},
            "listing_score_feeds_explain": [],
            "ns_reputation": {},
            "nschanges": {"results_summary": {}},
            "private_suffix_info": {},
            "sp_risk_score": 2,
            "sp_risk_score_explain": {"sp_risk_score_decider": "ns_entropy_score"},
        },
    ]
    mock_client.fetch_bulk_info.return_value = mock_response
    result = bulk_enrich_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Bulk.Enrich"
    assert result.outputs_key_field == args.get("resource")
    assert result.outputs == mock_response
    assert (
        result.readable_output
        == """# IP Information Results
Mocked Readable Output"""
    )


def test_get_domain_certificates_command(mock_client, mocker):
    args = {"domain": "example.com", "limit": "5"}
    mock_response = {
        "response": {
            "domain_certificates": [
                {
                    "certificate_id": "123",
                    "issuer": "Example Issuer",
                    "valid_from": "2023-01-01",
                    "valid_to": "2024-01-01",
                },
                {
                    "certificate_id": "456",
                    "issuer": "Another Issuer",
                    "valid_from": "2022-01-01",
                    "valid_to": "2023-01-01",
                },
            ],
            "metadata": {"total": 2},
        }
    }
    mock_client._http_request.return_value = mock_response
    result = get_domain_certificates_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Certificate"
    assert result.outputs_key_field == "domain"
    assert result.outputs["domain"] == "example.com"
    assert len(result.outputs["certificates"]) == 2
    assert result.readable_output.startswith("# SSL/TLS Certificate Information for Domain: example.com")


def test_get_domain_certificates_command_no_domain(mock_client):
    with pytest.raises(DemistoException, match="The 'domain' parameter is required."):
        get_domain_certificates_command(mock_client, {})


def test_get_domain_certificates_command_job_status(mock_client, mocker):
    args = {"domain": "example.com", "limit": "5"}
    job_details = {
        "get": "https://api.silentpush.com/api/v1/merge-api/explore/job/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "job_id": "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
        "status": "STARTED",
    }
    readable_output = tableToMarkdown(
        "# This task is taking longer, please try again later or use the 'retry job' command\n", job_details, removeNull=True
    )
    mock_client._http_request.return_value = {"job_status": job_details}
    mock_client.format_job_command_response.return_value = CommandResults(
        outputs_prefix="SilentPush.Job",
        outputs_key_field="job_id",
        outputs=job_details,
        readable_output=readable_output,
    )
    mock_client.response_has_job.return_value = job_details
    result = get_domain_certificates_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Job"
    assert result.outputs_key_field == "job_id"
    assert result.outputs == job_details
    assert result.readable_output == readable_output


def test_live_url_scan_command(mock_client, mocker):
    args = {"url": "https://example.com", "platform": "Desktop", "os": "Windows", "browser": "Chrome", "region": "US"}
    mock_response = {
        "response": {
            "scan": {
                "status": "completed",
                "details": "Scan completed successfully",
                "screenshot_url": "https://example.com/screenshot.jpg",
            }
        }
    }
    mock_client.live_url_scan.return_value = mock_response
    mock_client.validate_url_scan_parameters.return_value = False
    result = live_url_scan_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.URLScan"
    assert result.outputs_key_field == "url"
    assert result.outputs["url"] == "https://example.com"
    assert result.outputs["scan_results"] == mock_response
    assert result.readable_output == "Mocked Readable Output"


def test_live_url_scan_command_no_url(mock_client):
    args = {}
    with pytest.raises(DemistoException, match="URL is a required parameter"):
        live_url_scan_command(mock_client, args)


def test_live_url_scan_command_invalid_parameters(mock_client, mocker):
    args = {
        "url": "https://example.com",
        "platform": "invalid_platform",
        "os": "invalid_os",
        "browser": "invalid_browser",
        "region": "invalid_region",
    }
    mock_client.validate_url_scan_parameters.return_value = "Invalid parameters provided"
    with pytest.raises(DemistoException, match="Invalid parameters provided"):
        live_url_scan_command(mock_client, args)


def test_search_scan_data_command(mock_client, mocker):
    args = {"query": "domain:example.com"}
    mock_response = {
        "data": [
            {"domain": "example.com", "ip": "192.168.1.1", "status": "active"},
            {"domain": "example.org", "ip": "192.168.1.2", "status": "inactive"},
        ]
    }
    mock_client.search_scan_data.return_value = mock_response
    result = search_scan_data_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ScanData"
    assert result.outputs_key_field == "domain"
    assert result.outputs["records"] == mock_response["data"]
    assert result.outputs["query"] == "domain:example.com"
    assert result.readable_output == "Mocked Markdown Table"


def test_search_scan_data_command_no_query(mock_client):
    with pytest.raises(ValueError, match="Query parameter is required"):
        search_scan_data_command(mock_client, {})


def test_search_scan_data_command_no_data(mock_client, mocker):
    args = {"query": "domain:example.com"}
    mock_response = {"response": {"scandata_raw": []}}
    mock_client.search_scan_data.return_value = mock_response
    result = search_scan_data_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ScanData"
    assert result.outputs is None
    assert result.readable_output == "No scan data records found"


def test_reverse_padns_lookup_command(mock_client, mocker):
    args = {"qtype": "A", "query": "example.com"}
    mock_response = {
        "response": {
            "records": [
                {"answer": "192.168.1.1", "type": "A", "ttl": 3600},
                {"answer": "192.168.1.2", "type": "A", "ttl": 3600},
            ]
        }
    }
    mock_client.lookup.return_value = (mock_response, "Mocked Markdown Table")
    result = reverse_padns_lookup_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ReversePADNSLookup"
    assert result.outputs_key_field == "qname"
    assert result.outputs["qtype"] == args.get("qtype")
    assert result.outputs["query"] == "example.com"
    assert result.outputs["records"] == mock_response.get("response").get("records")
    assert result.readable_output == "Mocked Markdown Table"


def test_forward_padns_lookup_command(mock_client, mocker):
    args = {"qtype": "A", "query": "example.com", "limit": "10"}
    mock_response = {
        "response": {
            "records": [
                {"answer": "192.168.1.1", "type": "A", "ttl": 3600},
                {"answer": "192.168.1.2", "type": "A", "ttl": 3600},
            ]
        }
    }
    mock_client.lookup.return_value = (mock_response, "Mocked Markdown Table")
    result = forward_padns_lookup_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.PADNSLookup"
    assert result.outputs_key_field == "qname"
    assert result.outputs["qtype"] == "A"
    assert result.outputs["query"] == "example.com"
    assert result.outputs["records"] == mock_response.get("response").get("records")
    assert result.readable_output == "Mocked Markdown Table"


def test_ipdiversity_lookup_command(mock_client, mocker):
    args = {"qtype": "A", "query": "example.com"}
    mock_response = {
        "error": "None",
        "response": {
            "records": [
                {
                    "asn_diversity": 1,
                    "host": "ibm.com",
                    "ip_diversity_all": 15,
                    "ip_diversity_groups": 15,
                    "timeline": [
                        {
                            "asn": "16625",
                            "asname": "AKAMAI-AS, US",
                            "first_seen": "2026-05-21 04:26:11",
                            "ip": "184.31.91.132",
                            "last_seen": "2026-05-26 15:24:06",
                        }
                    ],
                }
            ]
        },
        "status_code": 200,
    }
    mock_client.lookup.return_value = (mock_response, "Mocked Markdown Table")
    result = ip_diversity_lookup_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Lookup"
    assert result.outputs_key_field == "query"
    assert result.outputs == mock_response.get("response").get("records")
    assert result.readable_output == "Mocked Markdown Table"


def test_ipdiversity_patterns_command(mock_client, mocker):
    args = {"nsname": "*.example.com", "asn_diversity_min": 2}
    mock_response = {
        "error": "None",
        "response": {
            "records": [
                {"asn_diversity": 2, "host": "example.com", "ip_diversity_all": 2, "ip_diversity_groups": 1},
            ]
        },
        "status_code": 200,
    }
    mock_client._http_request.return_value = mock_response
    result = ip_diversity_patterns_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Domain"
    assert result.outputs_key_field == "host"
    assert result.outputs == mock_response.get("response").get("records")
    assert result.readable_output == "Mocked Markdown Table"


def test_multi_conditional_padns_lookup_command(mock_client, mocker):
    args = {"qtype": "A", "query": "example.com", "answer": "1.1.1.1"}
    mock_response = {
        "error": "None",
        "response": {
            "records": [
                {
                    "answer": "1.1.1.1",
                    "count": 28,
                    "first_seen": "2024-12-27 04:55:36",
                    "last_seen": "2026-04-15 22:22:23",
                    "nshash": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "query": "example.com",
                    "ttl": 86400,
                    "type": "A",
                }
            ]
        },
        "status_code": 200,
    }
    mock_client.lookup.return_value = (mock_response, "Mocked Markdown Table")
    result = multi_conditional_padns_lookup_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.MultiConditionalPADNSLookup"
    assert result.outputs_key_field == "qname"
    assert result.outputs["qtype"] == "A"
    assert result.outputs["query"] == "example.com"
    assert result.outputs["records"] == mock_response.get("response").get("records")
    assert result.readable_output == "Mocked Markdown Table"


def test_search_domains_command(mock_client, mocker):
    args = {
        "domain": "example.com",
        "start_date": "2023-01-01",
        "end_date": "2023-12-31",
        "risk_score_min": "10",
        "risk_score_max": "90",
        "limit": "5",
    }
    mock_response = {
        "response": {
            "records": [
                {"domain": "example.com", "risk_score": 85, "registrar": "Example Registrar"},
                {"domain": "example.org", "risk_score": 70, "registrar": "Another Registrar"},
            ]
        }
    }
    mock_client._http_request.return_value = mock_response
    result = search_domains_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Domain"
    assert result.outputs_key_field == "domain"
    assert result.outputs == mock_response.get("response").get("records")
    assert result.outputs[0]["domain"] == "example.com"
    assert result.readable_output == "Mocked Markdown Table"


def test_density_lookup_command(mock_client, mocker):
    args = {"qtype": "nssrv", "query": "example.com", "scope": "global"}

    mock_response = {
        "response": {"records": [{"name": "ns1.example.com", "density": 10}, {"name": "ns2.example.com", "density": 5}]}
    }
    mock_client.lookup.return_value = (mock_response, "Mocked Markdown Table")
    result = density_lookup_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Lookup"
    assert result.outputs_key_field == "query"
    assert result.outputs["qtype"] == "nssrv"
    assert result.outputs["query"] == "example.com"
    assert result.outputs["records"] == mock_response.get("response").get("records")
    assert result.readable_output == "Mocked Markdown Table"


def test_add_feed_command(mock_client):
    unique_name = f"TestFeed_{uuid.uuid4().hex[:6]}"
    args = {"name": unique_name, "type": "domain", "tags": "Test,Demo"}
    expected_output = f"SilentPush feed: {unique_name} of type: domain was added successfully."
    mock_response = {
        "name": unique_name,
        "type": "domain",
        "vendor": "SilentPush",
        "feed_description": "Test feed for unit testing",
        "category": "default",
        "tags": "Test,Demo",
    }
    mock_client.add_feed.return_value = mock_response
    result = add_feed_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Feed"
    assert result.outputs_key_field == "name"
    assert result.outputs["name"] == unique_name
    assert result.outputs["vendor"] == "SilentPush"
    assert expected_output in result.readable_output


def test_add_indicators_command(mock_client):
    test_uuid = str(uuid.uuid4())
    expected_output = f"Indicators: '['example.com', 'malicious.net']' were added successfully to SilentPush feed: '{test_uuid}'."
    args = {"feed_uuid": test_uuid, "indicators": ["example.com", "malicious.net"]}
    mock_response = {"feed_uuid": test_uuid, "added": 2, "indicators": ["example.com", "malicious.net"]}
    mock_client.add_indicators.return_value = {"created_or_updated": mock_response}
    result = add_indicators_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.AddIndicators"
    assert result.outputs_key_field == "feed_uuid"
    assert result.outputs["feed_uuid"] == test_uuid
    assert result.outputs["added"] == 2
    assert expected_output in result.readable_output


def test_add_indicators_tags_command(mock_client):
    test_uuid = str(uuid.uuid4())
    test_indicator = "example.com"
    test_tags = ["test", "phishing"]
    expected_output = "Indicator Tags: '['test', 'phishing']' added to indicator 'example.com"
    args = {"feed_uuid": test_uuid, "indicator_name": test_indicator, "tags": test_tags}
    mock_response = {"feed_uuid": test_uuid, "indicator_name": test_indicator, "tags_added": test_tags}
    mock_client.add_indicators_tags.return_value = mock_response
    result = add_indicators_tags_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.AddIndicatorTags"
    assert result.outputs_key_field == "feed_uuid"
    assert result.outputs["feed_uuid"] == test_uuid
    assert result.outputs["indicator_name"] == test_indicator
    assert result.outputs["tags_added"] == test_tags
    assert expected_output in result.readable_output


def test_add_feed_tags_command(mocker):
    args = {"feed_uuid": "abc123", "tags": "malware"}
    expected_output = "feed with uuid: abc123 was updated with tags: malware"
    mock_response = {"created_or_updated": [{"uuid": "8eb9c1b8-edbb-4081-9978-590f5c5a0319", "tag": "phishing"}]}
    expected_res = mock_response.get("created_or_updated")
    mock_client = mocker.Mock(spec=Client)
    mock_client.add_feed_tags.return_value = mock_response
    result = add_feed_tags_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.AddFeedTags"
    assert result.outputs_key_field == "feed_uuid"
    assert result.outputs == expected_res
    assert result.raw_response == expected_res
    assert expected_output in result.readable_output


def test_whois_command(mock_client, mocker):
    args = {"domain": "example.com"}
    mock_response = {
        "error": "None",
        "response": {
            "whois": [
                {
                    "address": "None",
                    "city": "None",
                    "country": "None",
                    "created": "Fri, 02 Apr 1993 05:00:00 GMT",
                    "date": 20260524,
                    "domain": "example.com",
                    "emails": [],
                    "expires": "Fri, 20 Oct 2034 19:56:17 GMT",
                    "name": "None",
                    "nameservers": [],
                    "org": "example.com",
                    "query": "example.com",
                    "registrar": "GoDaddy.com, LLC",
                    "state": "None",
                    "updated": "Tue, 03 Dec 2024 21:03:37 GMT",
                    "whois_server": "whois.godaddy.com",
                    "zipcode": "None",
                }
            ]
        },
        "status_code": 200,
    }
    mock_client._http_request.return_value = mock_response
    result = whois_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Whois"
    assert result.outputs_key_field == "whois"
    assert result.outputs["whois"] == mock_response.get("response").get("whois")[0]
    assert result.readable_output == "Mocked Markdown Table"


def test_run_threat_check_command(mock_client):
    args = {"type": "domain", "data": ["example.com"], "user_identifier": "test_user", "query": "test_query"}
    mock_response = {
        "type": "domain",
        "data": ["example.com"],
        "user_identifier": "test_user",
        "query": "test_query",
        "result": "benign",
    }
    mock_client.run_threat_check.return_value = mock_response
    result = run_threat_check_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.RunThreatCheck"
    assert result.outputs_key_field == "query"
    assert result.outputs["query"] == "test_query"
    assert result.outputs["result"] == "benign"
    assert result.readable_output == "Mocked Markdown Table"


def mock_file_response(content: bytes, status_code=200, headers=None) -> Response:
    response = Response()
    response.status_code = status_code
    response._content = content
    response.headers = headers or {
        "Content-Disposition": 'attachment; filename="export.csv"',
        "Content-Type": "application/octet-stream",
    }
    return response


def test_get_data_exports_command(mock_client):
    args = {
        "export_type": "iofa",
        "file_name": "iofa_report",
        "file_type": "csv",
    }
    content = b"test,data\n1,2"
    mock_response = mock_file_response(content)
    mock_client.get_data_exports.return_value = mock_response
    result = get_data_exports_command(mock_client, args)
    assert isinstance(result, dict)
    assert result["File"] == "iofa_report"
    assert result["Type"] == EntryType.ENTRY_INFO_FILE


def test_retry_job_command(mock_client, mocker):
    args = {"job_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}
    mock_response = {
        "response": {
            "domain_certificates": [
                {
                    "certificate_id": "123",
                    "issuer": "Example Issuer",
                    "valid_from": "2023-01-01",
                    "valid_to": "2024-01-01",
                },
                {
                    "certificate_id": "456",
                    "issuer": "Another Issuer",
                    "valid_from": "2022-01-01",
                    "valid_to": "2023-01-01",
                },
            ],
            "metadata": {"total": 2},
        }
    }
    mock_client._http_request.return_value = mock_response
    result = retry_job_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.RetryJob"
    assert result.outputs_key_field == "job_id"
    assert result.outputs == mock_response.get("response")
    assert result.readable_output == f"# Job Results for {args.get('job_id')}\nMocked Readable Output"
