"""Base Integration for Cortex XSOAR - Unit Tests file
Pytest Unit Tests: all funcion names must start with "test_"
More details: https://xsoar.pan.dev/docs/integrations/unit-testing
MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"
You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import pytest
from SilentPush import (
    Client,
    CommandResults,
    get_job_status_command,
    get_nameserver_reputation_command,
    get_subnet_reputation_command,
    get_asns_for_domain_command,
    list_domain_infratags_command,
    list_domain_information_command,
    get_ipv4_reputation_command,
    get_future_attack_indicators_command,
    list_ip_information_command,
    get_asn_takedown_reputation_command,
    get_asn_reputation_command,
    get_enrichment_data_command,
    get_domain_certificates_command,
    screenshot_url_command,
    live_url_scan_command,
    search_scan_data_command,
    reverse_padns_lookup_command,
    forward_padns_lookup_command,
    search_domains_command,
    density_lookup_command,
)
from CommonServerPython import DemistoException


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client(mocker):
    client = mocker.Mock(spec=Client)
    return client


def test_get_job_status_command_success(mock_client):
    """
    Test case: Successfully retrieving job status.
    """
    args_success = {
        "job_id": "d4067541-eafb-424c-98d3-de12d7a91331",
        "max_wait": "10",
        "status_only": "false",
        "force_metadata_on": "true",
        "force_metadata_off": "false",
    }
    mock_response_success = {
        "response": {
            "job_id": "d4067541-eafb-424c-98d3-de12d7a91331",
            "job_status": {"job_id": "d4067541-eafb-424c-98d3-de12d7a91331", "status": "PENDING"},
        }
    }
    mock_client.get_job_status.return_value = mock_response_success
    result = get_job_status_command(mock_client, args_success)
    assert result.outputs_prefix == "SilentPush.JobStatus"
    assert result.outputs_key_field == "job_id"
    assert result.outputs == mock_response_success["response"]
    assert "Job Status for Job ID: d4067541-eafb-424c-98d3-de12d7a91331" in result.readable_output


def test_get_job_status_command_missing_job_id(mock_client):
    """
    Test case: Missing job_id in arguments.
    """
    args_missing_job_id = {}
    with pytest.raises(DemistoException, match="job_id is a required parameter"):
        get_job_status_command(mock_client, args_missing_job_id)


def test_get_job_status_command_no_status_found(mock_client):
    """
    Test case: No job status found for the given job ID.
    """
    args_no_status = {"job_id": "d4067541-eafb-424c-98d3-de12d7a91331"}
    mock_response_no_status = {"response": {}}
    mock_client.get_job_status.return_value = mock_response_no_status
    with pytest.raises(DemistoException, match="No job status found for Job ID: d4067541-eafb-424c-98d3-de12d7a91331"):
        get_job_status_command(mock_client, args_no_status)


def test_get_nameserver_reputation_command_success(mock_client, mocker):
    args = {"nameserver": "example.com", "explain": "true", "limit": 10}

    mock_response = {
        "response": {
            "ns_server_reputation_history": [
                {"ns_server": "example.com", "reputation": "good", "details": "No issues found", "date": 20240101}
            ]
        }
    }

    mock_client.get_nameserver_reputation.return_value = mock_response["response"]["ns_server_reputation_history"]
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    result = get_nameserver_reputation_command(mock_client, args)

    mock_client.get_nameserver_reputation.assert_called_once_with("example.com", True, 10)
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.NameserverReputation"
    assert result.outputs_key_field == "ns_server"
    assert result.outputs["nameserver"] == "example.com"
    assert result.outputs["reputation_data"][0]["date"] == "2024-01-01"
    assert result.readable_output == "Mocked Markdown Table"


def test_get_nameserver_reputation_command_no_nameserver(mock_client):
    args = {"explain": "true"}
    with pytest.raises(ValueError, match="Nameserver is required."):
        get_nameserver_reputation_command(mock_client, args)


def test_get_nameserver_reputation_command_no_data(mock_client, mocker):
    args = {"nameserver": "example.com"}
    mock_client.get_nameserver_reputation.return_value = []

    result = get_nameserver_reputation_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs["reputation_data"] == []
    assert result.readable_output == "No valid reputation history found for nameserver: example.com"


def test_get_nameserver_reputation_command_date_formatting(mock_client, mocker):
    args = {"nameserver": "example.com"}
    mock_response = [
        {"ns_server": "example.com", "date": 20240215},
        {"ns_server": "example.com", "date": "not_a_date"},
    ]

    mock_client.get_nameserver_reputation.return_value = mock_response
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Table")

    result = get_nameserver_reputation_command(mock_client, args)
    assert result.outputs["reputation_data"][0]["date"] == "2024-02-15"
    assert result.outputs["reputation_data"][1]["date"] == "not_a_date"


def test_get_subnet_reputation_command_success(mock_client, mocker):
    # Mock arguments
    args = {"subnet": "192.168.1.0/24", "explain": "true", "limit": "5"}

    # Mock response from client
    mock_response = {
        "response": {
            "subnet_reputation_history": [
                {"subnet": "192.168.1.0/24", "reputation": "suspicious", "details": "Found in blacklist"}
            ]
        }
    }
    mock_client.get_subnet_reputation.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_subnet_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.SubnetReputation"
    assert result.outputs_key_field == "subnet"
    assert result.outputs["subnet"] == "192.168.1.0/24"
    assert result.outputs["reputation_history"] == mock_response["response"]["subnet_reputation_history"]
    assert result.readable_output == "Mocked Markdown Table"


def test_get_subnet_reputation_command_no_subnet(mock_client):
    # Mock arguments without subnet
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="Subnet is a required parameter."):
        get_subnet_reputation_command(mock_client, args)


def test_get_subnet_reputation_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {"subnet": "192.168.1.0/24", "explain": "false", "limit": "5"}

    # Mock response from client
    mock_response = {"response": {"subnet_reputation_history": []}}
    mock_client.get_subnet_reputation.return_value = mock_response

    # Call the function
    result = get_subnet_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.SubnetReputation"
    assert result.outputs_key_field == "subnet"
    assert result.outputs["subnet"] == "192.168.1.0/24"
    assert result.outputs["reputation_history"] == []
    assert result.readable_output == "No reputation history found for subnet: 192.168.1.0/24"


def test_get_asns_for_domain_command_success(mock_client, mocker):
    # Mock arguments
    args = {"domain": "example.com"}

    # Mock response from client
    mock_response = {
        "response": {"records": [{"domain_asns": {"12345": "Example ASN Description", "67890": "Another ASN Description"}}]}
    }
    mock_client.get_asns_for_domain.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_asns_for_domain_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.DomainASNs"
    assert result.outputs_key_field == "domain"
    assert result.outputs["domain"] == "example.com"
    assert result.outputs["asns"] == [
        {"ASN": "12345", "Description": "Example ASN Description"},
        {"ASN": "67890", "Description": "Another ASN Description"},
    ]
    assert result.readable_output == "Mocked Markdown Table"


def test_get_asns_for_domain_command_no_domain(mock_client):
    # Mock arguments without domain
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="Domain is a required parameter."):
        get_asns_for_domain_command(mock_client, args)


def test_get_asns_for_domain_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {"domain": "example.com"}

    # Mock response from client
    mock_response = {"response": {"records": []}}
    mock_client.get_asns_for_domain.return_value = mock_response

    # Call the function
    result = get_asns_for_domain_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.DomainASNs"
    assert result.outputs_key_field == "domain"
    assert result.outputs["domain"] == "example.com"
    assert result.outputs["asns"] == []
    assert result.readable_output == "No ASNs found for domain: example.com"


def test_list_domain_infratags_command_success(mock_client, mocker):
    args = {
        "domains": "example.com,example.org",
        "cluster": "true",
        "mode": "live",
        "match": "self",
        "as_of": "2023-01-01",
        "origin_uid": "12345",
    }

    mock_response = {
        "response": {
            "mode": "live",
            "infratags": [
                {"domain": "example.com", "tags": ["tag1", "tag2"]},
                {"domain": "example.org", "tags": ["tag3", "tag4"]},
            ],
            "tag_clusters": [
                {"cluster_name": "Cluster1", "tags": ["tag1", "tag2"]},
                {"cluster_name": "Cluster2", "tags": ["tag3", "tag4"]},
            ],
        }
    }

    mock_client.list_domain_infratags.return_value = mock_response
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Table")

    result = list_domain_infratags_command(mock_client, args)

    mock_client.list_domain_infratags.assert_called_once_with(
        ["example.com", "example.org"], True, mode="live", match="self", as_of="2023-01-01", origin_uid="12345"
    )

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.InfraTags"
    assert result.outputs_key_field == "domain"
    assert result.outputs == mock_response
    assert "Mocked Table" in result.readable_output


def test_list_domain_infratags_command_non_live_mode(mock_client):
    args = {"domains": "example.com", "mode": "live"}
    mock_response = {"response": {"mode": "historical"}}
    mock_client.list_domain_infratags.return_value = mock_response

    with pytest.raises(ValueError, match="Expected mode 'live' but got 'historical'"):
        list_domain_infratags_command(mock_client, args)


def test_list_domain_infratags_command_empty_domains(mock_client):
    # Test with empty domains and use_get=False
    args = {"domains": "", "use_get": "false"}

    with pytest.raises(ValueError, match='"domains" argument is required when using POST.'):
        list_domain_infratags_command(mock_client, args)


def test_list_domain_infratags_command_use_get(mock_client, mocker):
    # Test with use_get=True and no domains
    args = {"use_get": "true"}
    mock_response = {"response": {"mode": "live", "infratags": []}}
    mock_client.list_domain_infratags.return_value = mock_response
    mocker.patch("CommonServerPython.tableToMarkdown", return_value="Empty Table")

    result = list_domain_infratags_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs == mock_response


def test_list_domain_infratags_command_empty_response(mock_client, mocker):
    # Test with empty response
    args = {"domains": "example.com"}
    mock_response = {"response": {"mode": "live", "infratags": []}}
    mock_client.list_domain_infratags.return_value = mock_response

    result = list_domain_infratags_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert not result.outputs.get("response", {}).get("infratags")


def test_list_domain_infratags_command_invalid_response(mock_client):
    # Test with invalid response structure
    args = {"domains": "example.com"}
    mock_response = {"invalid": "response"}
    mock_client.list_domain_infratags.return_value = mock_response

    result = list_domain_infratags_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert not result.outputs.get("response", {}).get("infratags")


def test_list_domain_information_command_success(mock_client, mocker):
    # Mock arguments
    args = {"domains": "example.com,example.org", "fetch_risk_score": "true", "fetch_whois_info": "true"}

    # Mock response from client
    mock_response = {
        "domains": [
            {"domain": "example.com", "risk_score": 85, "whois_info": {"registrar": "Example Registrar"}},
            {"domain": "example.org", "risk_score": 70, "whois_info": {"registrar": "Another Registrar"}},
        ]
    }
    mock_client.list_domain_information.return_value = mock_response

    # Mock format_domain_information
    mocker.patch("SilentPush.format_domain_information", return_value="Mocked Markdown Table")

    # Call the function
    result = list_domain_information_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Domain"
    assert result.outputs_key_field == "domain"
    assert result.outputs == mock_response["domains"]
    assert result.readable_output == "Mocked Markdown Table"


def test_list_domain_information_command_no_domains(mock_client, mocker):
    # Mock arguments without domains
    args = {}

    # Mock parse_arguments to raise an exception
    mocker.patch("SilentPush.parse_arguments", side_effect=ValueError("Domains are required."))

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="Domains are required."):
        list_domain_information_command(mock_client, args)


def test_list_domain_information_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {"domains": "example.com", "fetch_risk_score": "false", "fetch_whois_info": "false"}

    # Mock response from client
    mock_response = {"domains": []}
    mock_client.list_domain_information.return_value = mock_response

    # Mock format_domain_information
    mocker.patch("SilentPush.format_domain_information", return_value="No domain information available.")

    # Call the function
    result = list_domain_information_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Domain"
    assert result.outputs_key_field == "domain"
    assert result.outputs == []
    assert result.readable_output == "No domain information available."


def test_get_ipv4_reputation_command_no_ipv4(mock_client):
    # Mock arguments without ipv4
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="IPv4 address is required"):
        get_ipv4_reputation_command(mock_client, args)


def test_get_future_attack_indicators_command_success(mock_client, mocker):
    args = {"feed_uuid": "test-feed-uuid", "page_no": "1", "page_size": "10"}

    # Mock response from client
    mock_response = [
        {"indicator": "192.168.1.1", "type": "IP", "confidence": "high"},
        {"indicator": "example.com", "type": "Domain", "confidence": "medium"},
    ]
    mock_client.get_future_attack_indicators.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_future_attack_indicators_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.FutureAttackIndicators"
    assert result.outputs_key_field == "feed_uuid"
    assert result.outputs == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_get_future_attack_indicators_command_no_feed_uuid(mock_client):
    # Mock arguments without feed_uuid
    args = {}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="feed_uuid is a required parameter"):
        get_future_attack_indicators_command(mock_client, args)


def test_get_future_attack_indicators_command_no_data(mock_client, mocker):
    args = {"feed_uuid": "test-feed-uuid", "page_no": "1", "page_size": "10"}

    # Mock response from client
    mock_response = []
    mock_client.get_future_attack_indicators.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="### SilentPush Future Attack Indicators\n**No entries.**")

    # Call the function
    result = get_future_attack_indicators_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.FutureAttackIndicators"
    assert result.outputs_key_field == "feed_uuid"
    assert result.outputs == []
    assert result.readable_output.strip() == "### SilentPush Future Attack Indicators\n**No entries.**"


def test_list_ip_information_command_success(mock_client, mocker):
    # Mock arguments
    args = {"ips": "192.168.1.1,2001:db8::ff00:42:8329"}

    # Mock validate_ips
    mocker.patch("SilentPush.validate_ips", return_value=(["192.168.1.1"], ["2001:db8::ff00:42:8329"]))

    # Mock gather_ip_information
    mocker.patch(
        "SilentPush.gather_ip_information",
        side_effect=[
            [{"ip": "192.168.1.1", "info": "IPv4 info"}],
            [{"ip": "2001:db8::ff00:42:8329", "info": "IPv6 info"}],
        ],
    )

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = list_ip_information_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IPInformation"
    assert result.outputs_key_field == "ip"
    assert result.outputs == [
        {"ip": "192.168.1.1", "info": "IPv4 info"},
        {"ip": "2001:db8::ff00:42:8329", "info": "IPv6 info"},
    ]
    assert result.readable_output == "Mocked Markdown Table"


def test_list_ip_information_command_no_ips(mock_client):
    # Mock arguments without ips
    args = {}

    # Call the function
    result = list_ip_information_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IPInformation"
    assert result.outputs_key_field == "ip"
    assert result.outputs == []
    assert result.readable_output == "The 'ips' parameter is required."


def test_list_ip_information_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {"ips": "192.168.1.1"}

    # Mock validate_ips
    mocker.patch("SilentPush.validate_ips", return_value=(["192.168.1.1"], []))

    # Mock gather_ip_information
    mocker.patch("SilentPush.gather_ip_information", return_value=[])

    # Call the function
    result = list_ip_information_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IPInformation"
    assert result.outputs_key_field == "ip"
    assert result.outputs == []
    assert result.readable_output == "No information found for IPs: 192.168.1.1"


def test_get_asn_takedown_reputation_command_success(mock_client, mocker):
    args = {"asn": "12345", "limit": "10", "explain": "true"}

    mock_response = {
        "asn": "12345",
        "takedown_reputation_history": [{"date": 20240101, "score": 80}, {"date": 20240201, "score": 85}],
    }
    mock_client.get_asn_takedown_reputation.return_value = mock_response

    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    result = get_asn_takedown_reputation_command(mock_client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ASNTakedownReputation"
    assert result.outputs_key_field == "asn"
    assert result.outputs == {
        "asn": "12345",
        "history": [
            {"date": "2024-01-01", "score": 80},
            {"date": "2024-02-01", "score": 85},
        ],
    }
    assert result.readable_output == "Mocked Markdown Table"


def test_get_asn_takedown_reputation_command_no_asn(mock_client):
    args = {}
    with pytest.raises(ValueError, match="ASN is a required parameter."):
        get_asn_takedown_reputation_command(mock_client, args)


def test_get_asn_takedown_reputation_command_invalid_limit(mock_client):
    args = {"asn": "12345", "limit": "invalid"}
    with pytest.raises(ValueError, match="Invalid argument:"):
        get_asn_takedown_reputation_command(mock_client, args)


def test_get_asn_takedown_reputation_command_no_data(mock_client):
    args = {"asn": "12345", "limit": "10", "explain": "false"}

    mock_response = {"asn": "12345"}
    mock_client.get_asn_takedown_reputation.return_value = mock_response

    result = get_asn_takedown_reputation_command(mock_client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ASNTakedownReputation"
    assert result.outputs_key_field == "asn"
    assert result.outputs == {"asn": "12345", "history": []}
    assert "No takedown reputation history found for ASN: 12345" in result.readable_output


def test_get_asn_reputation_command_success(mock_client, mocker):
    args = {"asn": "12345", "limit": "10", "explain": "true"}

    mock_raw_response = {
        "asn_reputation_history": [
            {
                "asn": 12345,
                "reputation_score": 85,
                "timestamp": "2024-01-22T10:00:00Z",
                "explanation": {"malicious_activity": 0.7, "spam_activity": 0.3},
            }
        ]
    }

    mock_processed_response = [
        {
            "asn": 12345,
            "reputation_score": 85,
            "timestamp": "2024-01-22T10:00:00Z",
            "explanation": {"malicious_activity": 0.7, "spam_activity": 0.3},
        }
    ]

    mock_client.get_asn_reputation.return_value = mock_raw_response

    mocker.patch("SilentPush.extract_and_sort_asn_reputation", return_value=mock_processed_response)
    mocker.patch("SilentPush.prepare_asn_reputation_table", return_value=mock_processed_response[0])
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    result = get_asn_reputation_command(mock_client, args)

    # Check that client was called with correct params
    called_args = mock_client.get_asn_reputation.call_args[0]
    assert called_args[0] == 12345
    assert called_args[1] == 10
    assert called_args[2] is True

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ASNReputation"
    assert result.outputs_key_field == "asn"
    assert result.outputs == mock_processed_response
    assert result.readable_output == "Mocked Markdown Table"
    assert result.raw_response == mock_raw_response


def test_get_asn_reputation_command_no_asn(mock_client):
    # Mock arguments without asn
    args = {}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="ASN is required."):
        get_asn_reputation_command(mock_client, args)


def test_get_asn_reputation_command_invalid_asn(mock_client):
    # Mock arguments with invalid ASN
    args = {"asn": "invalid"}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="Invalid ASN number"):
        get_asn_reputation_command(mock_client, args)


def test_get_asn_reputation_command_no_data(mock_client, mocker):
    args = {"asn": "12345"}

    mock_raw_response = {"asn_reputation_history": []}
    mock_client.get_asn_reputation.return_value = mock_raw_response

    mocker.patch("SilentPush.extract_and_sort_asn_reputation", return_value=[])

    result = get_asn_reputation_command(mock_client, args)

    # Check client call values using call_args
    called_args = mock_client.get_asn_reputation.call_args[0]
    assert called_args[0] == 12345
    assert called_args[1] is None
    assert called_args[2] is False

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ASNReputation"
    assert result.outputs == []
    assert "No reputation data found for ASN 12345" in result.readable_output
    assert result.raw_response == mock_raw_response


def test_get_asn_reputation_command_with_limit(mock_client, mocker):
    args = {"asn": "12345", "limit": "5"}

    mock_raw_response = {"asn_reputation_history": []}
    mock_client.get_asn_reputation.return_value = mock_raw_response

    mocker.patch("SilentPush.extract_and_sort_asn_reputation", return_value=[])

    result = get_asn_reputation_command(mock_client, args)

    called_args = mock_client.get_asn_reputation.call_args[0]
    assert called_args[0] == 12345
    assert called_args[1] == 5
    assert called_args[2] is False

    assert isinstance(result, CommandResults)
    assert result.outputs == []


def test_get_enrichment_data_command_success(mock_client, mocker):
    # Mock arguments
    args = {"resource": "ipv4", "value": "192.168.1.1", "explain": "true", "scan_data": "false"}

    # Mock response from client
    mock_response = {"value": "192.168.1.1", "reputation": "good", "details": "No malicious activity detected"}
    mock_client.get_enrichment_data.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_enrichment_data_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Enrichment"
    assert result.outputs_key_field == "value"
    assert result.outputs["value"] == "192.168.1.1"
    assert result.outputs["reputation"] == "good"
    assert result.readable_output == "Mocked Markdown Table"


def test_get_enrichment_data_command_invalid_resource(mock_client):
    # Mock arguments with invalid resource
    args = {"resource": "invalid_resource", "value": "192.168.1.1"}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="Invalid input: invalid_resource. Allowed values are"):
        get_enrichment_data_command(mock_client, args)


def test_get_enrichment_data_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {"resource": "ipv4", "value": "192.168.1.1", "explain": "false", "scan_data": "false"}

    # Mock response from client
    mock_response = {}
    mock_client.get_enrichment_data.return_value = mock_response

    # Call the function
    result = get_enrichment_data_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Enrichment"
    assert result.outputs_key_field == "value"
    assert result.outputs["value"] == "192.168.1.1"
    assert result.readable_output == "No enrichment data found for resource: 192.168.1.1"


def test_get_domain_certificates_command_success(mock_client, mocker):
    # Mock arguments
    args = {"domain": "example.com", "limit": "5"}

    # Mock response from client
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
    mock_client.get_domain_certificates.return_value = mock_response

    # Mock format_certificate_info
    mocker.patch("SilentPush.format_certificate_info", side_effect=lambda cert: cert)

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_domain_certificates_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Certificate"
    assert result.outputs_key_field == "domain"
    assert result.outputs["domain"] == "example.com"
    assert len(result.outputs["certificates"]) == 2
    assert result.readable_output.startswith("# SSL/TLS Certificate Information for Domain: example.com")


def test_get_domain_certificates_command_no_domain(mock_client):
    # Mock arguments without domain
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="The 'domain' parameter is required."):
        get_domain_certificates_command(mock_client, args)


def test_get_domain_certificates_command_no_certificates(mock_client, mocker):
    # Mock arguments
    args = {"domain": "example.com", "limit": "5"}

    # Mock response from client
    mock_response = {"response": {"domain_certificates": [], "metadata": {"total": 0}}}
    mock_client.get_domain_certificates.return_value = mock_response

    # Call the function
    result = get_domain_certificates_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Certificate"
    assert result.outputs_key_field == "domain"
    assert result.outputs["domain"] == "example.com"
    assert result.outputs["certificates"] == []
    assert result.readable_output == "No certificates found for domain: example.com"


def test_get_domain_certificates_command_job_status(mock_client, mocker):
    # Mock arguments
    args = {"domain": "example.com", "limit": "5"}

    # Mock response from client
    mock_response = {"response": {"job_status": {"status": "in_progress", "job_id": "12345"}}}
    mock_client.get_domain_certificates.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Job Status Table")

    # Call the function
    result = get_domain_certificates_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Certificate"
    assert result.outputs_key_field == "domain"
    assert result.outputs["domain"] == "example.com"
    assert result.outputs["job_details"] == {"status": "in_progress", "job_id": "12345"}
    assert result.readable_output == "Mocked Job Status Table"


def test_screenshot_url_command_success(mock_client, mocker):
    args = {"url": "https://example.com"}

    # Mock the client response
    mock_response = {"screenshot_url": "https://storage.com/path/screenshot.jpg", "status_code": 200}
    mock_client.screenshot_url.return_value = mock_response

    # Properly patch where the function is used, not defined
    mock_image_response = mocker.Mock()
    mock_image_response.status_code = 200
    mock_image_response.content = b"image content"
    mocker.patch("SilentPush.generic_http_request", return_value=mock_image_response)

    mock_file_result = mocker.patch("SilentPush.fileResult", return_value={"Type": 3, "FileID": "123"})
    mock_return_results = mocker.patch("SilentPush.return_results")

    # Run command
    result = screenshot_url_command(mock_client, args)

    # Validate
    assert isinstance(result, CommandResults)
    assert result.outputs["url"] == "https://example.com"
    assert result.outputs["status"] == "success"
    assert result.outputs["screenshot_url"] == mock_response["screenshot_url"]
    assert result.outputs["file_name"] == "example.com_screenshot.jpg"

    mock_file_result.assert_called_once_with("example.com_screenshot.jpg", mock_image_response.content)
    mock_return_results.assert_called_once()


def test_screenshot_url_command_no_url(mock_client):
    # Test with empty args
    with pytest.raises(ValueError, match="URL is required"):
        screenshot_url_command(mock_client, {})


def test_screenshot_url_command_missing_screenshot_url(mock_client):
    args = {"url": "https://example.com"}
    mock_client.screenshot_url.return_value = {"status": "success"}

    with pytest.raises(ValueError, match="screenshot_url is missing from API response"):
        screenshot_url_command(mock_client, args)


def test_screenshot_url_command_error_from_api(mock_client):
    args = {"url": "https://example.com"}
    mock_client.screenshot_url.return_value = {"error": "API Error"}

    with pytest.raises(Exception, match="API Error"):
        screenshot_url_command(mock_client, args)


def test_screenshot_url_command_invalid_screenshot_url(mock_client):
    args = {"url": "https://example.com"}
    mock_client.screenshot_url.return_value = {"screenshot_url": "invalid_url"}

    with pytest.raises(ValueError, match="Invalid screenshot URL format"):
        screenshot_url_command(mock_client, args)


def test_screenshot_url_command_failed_image_download(mock_client, mocker):
    args = {"url": "https://example.com"}
    mock_response = {"screenshot_url": "https://storage.com/path/screenshot.jpg"}
    mock_client.screenshot_url.return_value = mock_response

    mock_image_response = mocker.Mock()
    mock_image_response.status_code = 404

    mocker.patch("SilentPush.generic_http_request", return_value=mock_image_response)

    result = screenshot_url_command(mock_client, args)
    assert isinstance(result, dict)
    assert result["error"] == "Failed to download screenshot image: HTTP 404"


def test_live_url_scan_command_success(mock_client, mocker):
    # Mock arguments
    args = {"url": "https://example.com", "platform": "Desktop", "os": "Windows", "browser": "Chrome", "region": "US"}

    # Mock response from client
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

    # Mock format_scan_results
    mocker.patch("SilentPush.format_scan_results", return_value=("Mocked Readable Output", mock_response["response"]["scan"]))

    # Call the function
    result = live_url_scan_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.URLScan"
    assert result.outputs_key_field == "url"
    assert result.outputs["url"] == "https://example.com"
    assert result.outputs["scan_results"] == mock_response["response"]["scan"]
    assert result.readable_output == "Mocked Readable Output"


def test_live_url_scan_command_no_url(mock_client):
    # Mock arguments without URL
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="URL is a required parameter"):
        live_url_scan_command(mock_client, args)


def test_live_url_scan_command_invalid_parameters(mock_client, mocker):
    # Mock arguments with invalid parameters
    args = {
        "url": "https://example.com",
        "platform": "invalid_platform",
        "os": "invalid_os",
        "browser": "invalid_browser",
        "region": "invalid_region",
    }

    # Mock validate_parameters to return validation errors
    mocker.patch("SilentPush.validate_parameters", return_value="Invalid parameters provided")

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="Invalid parameters provided"):
        live_url_scan_command(mock_client, args)


def test_live_url_scan_command_no_scan_results(mock_client, mocker):
    # Mock arguments
    args = {"url": "https://example.com", "platform": "Desktop", "os": "Windows", "browser": "Chrome", "region": "US"}

    # Mock response from client with no scan results
    mock_response = {"response": {"scan": {}}}
    mock_client.live_url_scan.return_value = mock_response

    # Mock format_scan_results
    mocker.patch("SilentPush.format_scan_results", return_value=("No scan results available", {}))

    # Call the function
    result = live_url_scan_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.URLScan"
    assert result.outputs_key_field == "url"
    assert result.outputs["url"] == "https://example.com"
    assert result.outputs["scan_results"] == {}
    assert result.readable_output == "No scan results available"


def test_search_scan_data_command_success(mock_client, mocker):
    # Mock arguments
    args = {"query": "domain:example.com"}

    # Mock response from client
    mock_response = {
        "response": {
            "scandata_raw": [
                {"domain": "example.com", "ip": "192.168.1.1", "status": "active"},
                {"domain": "example.org", "ip": "192.168.1.2", "status": "inactive"},
            ]
        }
    }
    mock_client.search_scan_data.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = search_scan_data_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ScanData"
    assert result.outputs_key_field == "domain"
    assert result.outputs["records"] == mock_response["response"]["scandata_raw"]
    assert result.outputs["query"] == "domain:example.com"
    assert result.readable_output == "Mocked Markdown Table"


def test_search_scan_data_command_no_query(mock_client):
    # Mock arguments without query
    args = {}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="Query parameter is required"):
        search_scan_data_command(mock_client, args)


def test_search_scan_data_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {"query": "domain:example.com"}

    # Mock response from client with no data
    mock_response = {"response": {"scandata_raw": []}}
    mock_client.search_scan_data.return_value = mock_response

    # Call the function
    result = search_scan_data_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ScanData"
    assert result.outputs is None
    assert result.readable_output == "No scan data records found"


def test_reverse_padns_lookup_command_success(mock_client, mocker):
    # Mock arguments
    args = {"qtype": "A", "qname": "example.com"}

    # Mock response from client
    mock_response = {
        "response": {
            "records": [
                {"answer": "192.168.1.1", "type": "A", "ttl": 3600},
                {"answer": "192.168.1.2", "type": "A", "ttl": 3600},
            ]
        }
    }
    mock_client.reverse_padns_lookup.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = reverse_padns_lookup_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ReversePADNSLookup"
    assert result.outputs_key_field == "qname"
    assert result.outputs["qtype"] == "A"
    assert result.outputs["qname"] == "example.com"
    assert len(result.outputs["records"]) == 2
    assert result.readable_output == "Mocked Markdown Table"


def test_reverse_padns_lookup_command_no_qtype_or_qname(mock_client):
    # Mock arguments without qtype and qname
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="Both 'qtype' and 'qname' are required parameters."):
        reverse_padns_lookup_command(mock_client, args)


def test_reverse_padns_lookup_command_no_records(mock_client, mocker):
    # Mock arguments
    args = {"qtype": "A", "qname": "example.com"}

    # Mock response from client with no records
    mock_response = {"response": {"records": []}}
    mock_client.reverse_padns_lookup.return_value = mock_response

    # Call the function
    result = reverse_padns_lookup_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ReversePADNSLookup"
    assert result.outputs_key_field == "qname"
    assert result.outputs["qtype"] == "A"
    assert result.outputs["qname"] == "example.com"
    assert result.outputs["records"] == []
    assert result.readable_output == "No records found for A example.com"


def test_reverse_padns_lookup_command_api_error(mock_client):
    # Mock arguments
    args = {"qtype": "A", "qname": "example.com"}

    # Mock response from client with an error
    mock_response = {"error": "Invalid query"}
    mock_client.reverse_padns_lookup.return_value = mock_response

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="API Error: Invalid query"):
        reverse_padns_lookup_command(mock_client, args)


def test_forward_padns_lookup_command_success(mock_client, mocker):
    # Mock arguments
    args = {"qtype": "A", "qname": "example.com", "limit": "10"}

    # Mock response from client
    mock_response = {
        "response": {
            "records": [
                {"answer": "192.168.1.1", "type": "A", "ttl": 3600},
                {"answer": "192.168.1.2", "type": "A", "ttl": 3600},
            ]
        }
    }
    mock_client.forward_padns_lookup.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = forward_padns_lookup_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.PADNSLookup"
    assert result.outputs_key_field == "qname"
    assert result.outputs["qtype"] == "A"
    assert result.outputs["qname"] == "example.com"
    assert len(result.outputs["records"]) == 2
    assert result.readable_output == "Mocked Markdown Table"


def test_forward_padns_lookup_command_no_qtype_or_qname(mock_client):
    # Mock arguments without qtype and qname
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="Both 'qtype' and 'qname' are required parameters."):
        forward_padns_lookup_command(mock_client, args)


def test_forward_padns_lookup_command_no_records(mock_client, mocker):
    # Mock arguments
    args = {"qtype": "A", "qname": "example.com"}

    # Mock response from client with no records
    mock_response = {"response": {"records": []}}
    mock_client.forward_padns_lookup.return_value = mock_response

    # Call the function
    result = forward_padns_lookup_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.PADNSLookup"
    assert result.outputs_key_field == "qname"
    assert result.outputs["qtype"] == "A"
    assert result.outputs["qname"] == "example.com"
    assert result.outputs["records"] == []
    assert result.readable_output == "No records found for A example.com"


def test_forward_padns_lookup_command_api_error(mock_client):
    # Mock arguments
    args = {"qtype": "A", "qname": "example.com"}

    # Mock response from client with an error
    mock_response = {"error": "Invalid query"}
    mock_client.forward_padns_lookup.return_value = mock_response

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="API Error: Invalid query"):
        forward_padns_lookup_command(mock_client, args)


def test_search_domains_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "domain": "example.com",
        "start_date": "2023-01-01",
        "end_date": "2023-12-31",
        "risk_score_min": "10",
        "risk_score_max": "90",
        "limit": "5",
    }

    # Mock response from client
    mock_response = {
        "response": {
            "records": [
                {"domain": "example.com", "risk_score": 85, "registrar": "Example Registrar"},
                {"domain": "example.org", "risk_score": 70, "registrar": "Another Registrar"},
            ]
        }
    }
    mock_client.search_domains.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = search_domains_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Domain"
    assert result.outputs_key_field == "domain"
    assert len(result.outputs) == 2
    assert result.outputs[0]["domain"] == "example.com"
    assert result.readable_output == "Mocked Markdown Table"


def test_search_domains_command_no_records(mock_client, mocker):
    # Mock arguments
    args = {"domain": "nonexistent.com", "limit": "5"}

    # Mock response from client with no records
    mock_response = {"response": {"records": []}}
    mock_client.search_domains.return_value = mock_response

    # Call the function
    result = search_domains_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Domain"
    assert result.outputs == []
    assert result.readable_output == "No domains found."


def test_search_domains_command_invalid_arguments(mock_client):
    # Mock arguments with invalid data
    args = {"risk_score_min": "invalid", "risk_score_max": "invalid"}

    # Call the function and expect ValueError
    with pytest.raises(ValueError):
        search_domains_command(mock_client, args)


def test_density_lookup_command_success(mock_client, mocker):
    # Mock arguments
    args = {"qtype": "nssrv", "query": "example.com", "scope": "global"}

    # Mock response from client
    mock_response = {
        "response": {"records": [{"name": "ns1.example.com", "density": 10}, {"name": "ns2.example.com", "density": 5}]}
    }
    mock_client.density_lookup.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = density_lookup_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.$Lookup"
    assert result.outputs_key_field == "query"
    assert result.outputs["qtype"] == "nssrv"
    assert result.outputs["query"] == "example.com"
    assert len(result.outputs["records"]) == 2
    assert result.readable_output == "Mocked Markdown Table"


def test_density_lookup_command_no_qtype_or_query(mock_client):
    # Mock arguments without qtype and query
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="Both 'qtype' and 'query' are required parameters."):
        density_lookup_command(mock_client, args)


def test_density_lookup_command_no_records(mock_client, mocker):
    # Mock arguments
    args = {"qtype": "nssrv", "query": "nonexistent.com"}

    # Mock response from client with no records
    mock_response = {"response": {"records": []}}
    mock_client.density_lookup.return_value = mock_response

    # Call the function
    result = density_lookup_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.$Lookup"
    assert result.outputs_key_field == "query"
    assert result.outputs["qtype"] == "nssrv"
    assert result.outputs["query"] == "nonexistent.com"
    assert result.outputs["records"] == []
    assert result.readable_output == "No density records found for nssrv nonexistent.com"


def test_density_lookup_command_api_error(mock_client):
    # Mock arguments
    args = {"qtype": "nssrv", "query": "example.com"}

    # Mock response from client with an error
    mock_response = {"error": "Invalid query"}
    mock_client.density_lookup.return_value = mock_response

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="API Error: Invalid query"):
        density_lookup_command(mock_client, args)
