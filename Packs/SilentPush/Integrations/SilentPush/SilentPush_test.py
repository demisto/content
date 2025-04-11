"""Base Integration for Cortex XSOAR - Unit Tests file
Pytest Unit Tests: all funcion names must start with "test_"
More details: https://xsoar.pan.dev/docs/integrations/unit-testing
MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"
You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""
import json
import pytest
from SilentPush import Client, CommandResults, get_job_status_command, get_nameserver_reputation_command, get_subnet_reputation_command, get_asns_for_domain_command, list_domain_infratags_command, list_domain_information_command, get_ipv4_reputation_command, get_future_attack_indicators_command, list_ip_information_command, get_asn_takedown_reputation_command, get_asn_reputation_command, get_enrichment_data_command, get_domain_certificates_command, screenshot_url_command, live_url_scan_command, search_scan_data_command, reverse_padns_lookup_command, forward_padns_lookup_command, search_domains_command, density_lookup_command
from CommonServerPython import DemistoException
from requests.models import Response


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
        "force_metadata_off": "false"
    }
    mock_response_success = {
        "response": {
            "job_id": "d4067541-eafb-424c-98d3-de12d7a91331",
            "job_status": {
                "job_id": "d4067541-eafb-424c-98d3-de12d7a91331",
                "status": "PENDING"
            }
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
    args_no_status = {
        "job_id": "d4067541-eafb-424c-98d3-de12d7a91331"
    }
    mock_response_no_status = {
        "response": {}
    }
    mock_client.get_job_status.return_value = mock_response_no_status
    with pytest.raises(DemistoException, match="No job status found for Job ID: d4067541-eafb-424c-98d3-de12d7a91331"):
        get_job_status_command(mock_client, args_no_status)


def test_get_nameserver_reputation_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "nameserver": "example.com",
        "explain": "true",
        "limit": "10"
    }

    # Mock response from client
    mock_response = [
        {"ns_server": "example.com", "reputation": "good", "details": "No issues found"}
    ]
    mock_client.get_nameserver_reputation.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_nameserver_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.NameserverReputation"
    assert result.outputs_key_field == "ns_server"
    assert result.outputs["nameserver"] == "example.com"
    assert result.outputs["reputation_data"] == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_get_nameserver_reputation_command_no_nameserver(mock_client):
    # Mock arguments without nameserver
    args = {}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="Nameserver is required."):
        get_nameserver_reputation_command(mock_client, args)


def test_get_nameserver_reputation_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {
        "nameserver": "example.com",
        "explain": "false",
        "limit": "5"
    }

    # Mock response from client
    mock_client.get_nameserver_reputation.return_value = []

    # Call the function
    result = get_nameserver_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.NameserverReputation"
    assert result.outputs_key_field == "ns_server"
    assert result.outputs["nameserver"] == "example.com"
    assert result.outputs["reputation_data"] == []
    assert result.readable_output == "No reputation history found for nameserver: example.com"


def test_get_subnet_reputation_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "subnet": "192.168.1.0/24",
        "explain": "true",
        "limit": "5"
    }

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
    args = {
        "subnet": "192.168.1.0/24",
        "explain": "false",
        "limit": "5"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "subnet_reputation_history": []
        }
    }
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
    args = {
        "domain": "example.com"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "records": [
                {
                    "domain_asns": {
                        "12345": "Example ASN Description",
                        "67890": "Another ASN Description"
                    }
                }
            ]
        }
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
        {"ASN": "67890", "Description": "Another ASN Description"}
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
    args = {
        "domain": "example.com"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "records": []
        }
    }
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
    # Mock arguments
    args = {
        "domains": "example.com,example.org",
        "cluster": "true",
        "mode": "live",
        "match": "self",
        "as_of": "2023-01-01",
        "origin_uid": "12345",
        "use_get": "false"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "infratags": [
                {"domain": "example.com", "tag": "tag1"},
                {"domain": "example.org", "tag": "tag2"}
            ],
            "tag_clusters": [
                {"cluster_name": "Cluster1", "tags": ["tag1", "tag2"]}
            ]
        }
    }
    mock_client.list_domain_infratags.return_value = mock_response

    # Mock tableToMarkdown and format_tag_clusters
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")
    mocker.patch("SilentPush.format_tag_clusters", return_value="\nMocked Cluster Details")

    # Call the function
    result = list_domain_infratags_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.InfraTags"
    assert result.outputs_key_field == "domain"
    assert result.outputs == mock_response
    assert "Mocked Markdown Table" in result.readable_output
    assert "Mocked Cluster Details" in result.readable_output


def test_list_domain_infratags_command_no_domains(mock_client):
    # Mock arguments without domains
    args = {
        "use_get": "false"
    }

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match='"domains" argument is required when using POST.'):
        list_domain_infratags_command(mock_client, args)


def test_list_domain_infratags_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {
        "domains": "example.com",
        "cluster": "false",
        "use_get": "true"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "infratags": [],
            "tag_clusters": []
        }
    }
    mock_client.list_domain_infratags.return_value = mock_response

    # Call the function
    result = list_domain_infratags_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.InfraTags"
    assert result.outputs_key_field == "domain"
    assert result.outputs == mock_response
    assert result.readable_output.strip() == "### Domain Infratags\n**No entries.**"


def test_list_domain_information_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "domains": "example.com,example.org",
        "fetch_risk_score": "true",
        "fetch_whois_info": "true"
    }

    # Mock response from client
    mock_response = {
        "domains": [
            {"domain": "example.com", "risk_score": 85, "whois_info": {"registrar": "Example Registrar"}},
            {"domain": "example.org", "risk_score": 70, "whois_info": {"registrar": "Another Registrar"}}
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
    args = {
        "domains": "example.com",
        "fetch_risk_score": "false",
        "fetch_whois_info": "false"
    }

    # Mock response from client
    mock_response = {
        "domains": []
    }
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


def test_get_ipv4_reputation_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "ipv4": "192.168.1.1",
        "explain": "true",
        "limit": "1"
    }

    # Mock response from client
    mock_response = [
        {
            "ip": "192.168.1.1",
            "date": "2023-01-01",
            "ip_reputation": 85,
            "ip_reputation_explain": {
                "ip_density": 0.5,
                "names_num_listed": 10
            }
        }
    ]
    mock_client.get_ipv4_reputation.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_ipv4_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IPv4Reputation"
    assert result.outputs_key_field == "ip"
    assert result.outputs["ip"] == "192.168.1.1"
    assert result.outputs["reputation_score"] == 85
    assert result.outputs["ip_reputation_explain"] == {
        "ip_density": 0.5,
        "names_num_listed": 10
    }
    assert result.readable_output == "Mocked Markdown Table"


def test_get_ipv4_reputation_command_no_ipv4(mock_client):
    # Mock arguments without ipv4
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="IPv4 address is required"):
        get_ipv4_reputation_command(mock_client, args)


def test_get_ipv4_reputation_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {
        "ipv4": "192.168.1.1",
        "explain": "false",
        "limit": "1"
    }

    # Mock response from client
    mock_response = []
    mock_client.get_ipv4_reputation.return_value = mock_response

    # Call the function
    result = get_ipv4_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IPv4Reputation"
    assert result.outputs_key_field == "ip"
    assert result.outputs["ip"] == "192.168.1.1"
    assert result.readable_output == "No reputation data found for IPv4: 192.168.1.1"


def test_get_future_attack_indicators_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "feed_uuid": "test-feed-uuid",
        "page_no": "1",
        "page_size": "10"
    }

    # Mock response from client
    mock_response = [
        {"indicator": "192.168.1.1", "type": "IP", "confidence": "high"},
        {"indicator": "example.com", "type": "Domain", "confidence": "medium"}
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
    assert result.outputs["feed_uuid"] == "test-feed-uuid"
    assert result.outputs["page_no"] == 1
    assert result.outputs["page_size"] == 10
    assert result.outputs["indicators"] == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_get_future_attack_indicators_command_no_feed_uuid(mock_client):
    # Mock arguments without feed_uuid
    args = {}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="feed_uuid is a required parameter"):
        get_future_attack_indicators_command(mock_client, args)


def test_get_future_attack_indicators_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {
        "feed_uuid": "test-feed-uuid",
        "page_no": "1",
        "page_size": "10"
    }

    # Mock response from client
    mock_response = []
    mock_client.get_future_attack_indicators.return_value = mock_response

    # Call the function
    result = get_future_attack_indicators_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.FutureAttackIndicators"
    assert result.outputs_key_field == "feed_uuid"
    assert result.outputs["feed_uuid"] == "test-feed-uuid"
    assert result.outputs["page_no"] == 1
    assert result.outputs["page_size"] == 10
    assert result.outputs["indicators"] == []
    assert result.readable_output.strip() == "### # Future Attack Indicators\nFeed UUID: test-feed-uuid\n\n**No entries.**"


def test_list_ip_information_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "ips": "192.168.1.1,2001:db8::ff00:42:8329"
    }

    # Mock validate_ips
    mocker.patch("SilentPush.validate_ips", return_value=(["192.168.1.1"], ["2001:db8::ff00:42:8329"]))

    # Mock gather_ip_information
    mocker.patch("SilentPush.gather_ip_information", side_effect=[
        [{"ip": "192.168.1.1", "info": "IPv4 info"}],
        [{"ip": "2001:db8::ff00:42:8329", "info": "IPv6 info"}]
    ])

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
        {"ip": "2001:db8::ff00:42:8329", "info": "IPv6 info"}
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
    args = {
        "ips": "192.168.1.1"
    }

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


def test_get_ipv4_reputation_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "ipv4": "192.168.1.1",
        "explain": "true",
        "limit": "1"
    }

    # Mock validate_ip
    mocker.patch("SilentPush.validate_ip", return_value=True)

    # Mock response from client
    mock_response = [
        {
            "ip": "192.168.1.1",
            "date": "2023-01-01",
            "ip_reputation": 85,
            "ip_reputation_explain": {
                "ip_density": 0.5,
                "names_num_listed": 10
            }
        }
    ]
    mock_client.get_ipv4_reputation.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_ipv4_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IPv4Reputation"
    assert result.outputs_key_field == "ip"
    assert result.outputs["ip"] == "192.168.1.1"
    assert result.outputs["reputation_score"] == 85
    assert result.outputs["ip_reputation_explain"] == {
        "ip_density": 0.5,
        "names_num_listed": 10
    }
    assert result.readable_output == "Mocked Markdown Table"


def test_get_ipv4_reputation_command_no_ipv4(mock_client):
    # Mock arguments without ipv4
    args = {}

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="IPv4 address is required"):
        get_ipv4_reputation_command(mock_client, args)


def test_get_ipv4_reputation_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {
        "ipv4": "192.168.1.1",
        "explain": "false",
        "limit": "1"
    }

    # Mock validate_ip
    mocker.patch("SilentPush.validate_ip", return_value=True)

    # Mock response from client
    mock_response = []
    mock_client.get_ipv4_reputation.return_value = mock_response

    # Call the function
    result = get_ipv4_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.IPv4Reputation"
    assert result.outputs_key_field == "ip"
    assert result.outputs["ip"] == "192.168.1.1"
    assert result.readable_output == "No reputation data found for IPv4: 192.168.1.1"


def test_get_asn_takedown_reputation_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "asn": "12345",
        "limit": "10",
        "explain": "true"
    }

    # Mock response from client
    mock_response = {
        "asn": "12345",
        "reputation_score": 85,
        "details": "ASN is associated with malicious activity"
    }
    mock_client.get_asn_takedown_reputation.return_value = mock_response

    # Mock tableToMarkdown
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_asn_takedown_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ASNTakedownReputation"
    assert result.outputs_key_field == "asn"
    assert result.outputs == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_get_asn_takedown_reputation_command_no_asn(mock_client):
    # Mock arguments without asn
    args = {}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="ASN is a required parameter"):
        get_asn_takedown_reputation_command(mock_client, args)


def test_get_asn_takedown_reputation_command_invalid_limit(mock_client):
    # Mock arguments with invalid limit
    args = {
        "asn": "12345",
        "limit": "invalid"
    }

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="Limit must be a valid number"):
        get_asn_takedown_reputation_command(mock_client, args)


def test_get_asn_takedown_reputation_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {
        "asn": "12345",
        "limit": "10",
        "explain": "false"
    }

    # Mock response from client
    mock_client.get_asn_takedown_reputation.return_value = None

    # Call the function
    result = get_asn_takedown_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ASNTakedownReputation"
    assert result.outputs is None
    assert result.readable_output == "No takedown reputation data found for ASN 12345"


def test_get_asn_reputation_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "asn": "12345",
        "limit": "10",
        "explain": "true"
    }

    # Mock response from client
    mock_response = [
        {"asn": "12345", "reputation_score": 85, "details": "ASN is associated with suspicious activity"}
    ]
    mock_client.get_asn_reputation.return_value = mock_response

    # Mock helper functions
    mocker.patch("SilentPush.extract_and_sort_asn_reputation", return_value=mock_response)
    mocker.patch("SilentPush.prepare_asn_reputation_table", return_value=mock_response)
    mocker.patch("SilentPush.get_table_headers", return_value=["asn", "reputation_score", "details"])
    mocker.patch("SilentPush.tableToMarkdown", return_value="Mocked Markdown Table")

    # Call the function
    result = get_asn_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ASNReputation"
    assert result.outputs_key_field == "asn"
    assert result.outputs == mock_response
    assert result.readable_output == "Mocked Markdown Table"


def test_get_asn_reputation_command_no_asn(mock_client):
    # Mock arguments without asn
    args = {}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="ASN is required."):
        get_asn_reputation_command(mock_client, args)


def test_get_asn_reputation_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {
        "asn": "12345",
        "limit": "10",
        "explain": "false"
    }

    # Mock response from client
    mock_response = []
    mock_client.get_asn_reputation.return_value = mock_response

    # Mock helper functions
    mocker.patch("SilentPush.extract_and_sort_asn_reputation", return_value=[])
    mocker.patch("SilentPush.generate_no_reputation_response", return_value=CommandResults(
        readable_output="No reputation data found for ASN 12345",
        outputs_prefix="SilentPush.ASNReputation",
        outputs=None
    ))

    # Call the function
    result = get_asn_reputation_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.ASNReputation"
    assert result.outputs is None
    assert result.readable_output == "No reputation data found for ASN 12345"


def test_get_enrichment_data_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "resource": "ipv4",
        "value": "192.168.1.1",
        "explain": "true",
        "scan_data": "false"
    }

    # Mock response from client
    mock_response = {
        "value": "192.168.1.1",
        "reputation": "good",
        "details": "No malicious activity detected"
    }
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
    args = {
        "resource": "invalid_resource",
        "value": "192.168.1.1"
    }

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="Invalid input: invalid_resource. Allowed values are"):
        get_enrichment_data_command(mock_client, args)


def test_get_enrichment_data_command_no_data(mock_client, mocker):
    # Mock arguments
    args = {
        "resource": "ipv4",
        "value": "192.168.1.1",
        "explain": "false",
        "scan_data": "false"
    }

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
    args = {
        "domain": "example.com",
        "limit": "5"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "domain_certificates": [
                {"certificate_id": "123", "issuer": "Example Issuer", "valid_from": "2023-01-01", "valid_to": "2024-01-01"},
                {"certificate_id": "456", "issuer": "Another Issuer", "valid_from": "2022-01-01", "valid_to": "2023-01-01"}
            ],
            "metadata": {"total": 2}
        }
    }
    mock_client.get_domain_certificates.return_value = mock_response

    # Mock format_certificate_info
    mocker.patch("SilentPush.format_certificate_info", side_effect=lambda cert, client: cert)

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
    args = {
        "domain": "example.com",
        "limit": "5"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "domain_certificates": [],
            "metadata": {"total": 0}
        }
    }
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
    args = {
        "domain": "example.com",
        "limit": "5"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "job_status": {"status": "in_progress", "job_id": "12345"}
        }
    }
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
    # Mock arguments
    args = {
        "url": "https://example.com"
    }

    # Mock response from client
    mock_response = {
        "screenshot_url": "https://example.com/screenshot.jpg",
        "status_code": 200
    }
    mock_client.screenshot_url.return_value = mock_response

    # Mock requests.get
    mock_image_response = mocker.Mock(spec=Response)
    mock_image_response.status_code = 200
    mock_image_response.content = b"image content"
    mocker.patch("requests.get", return_value=mock_image_response)

    # Mock fileResult
    mocker.patch("SilentPush.fileResult", return_value={"Type": 3, "FileID": "123", "File": "example_screenshot.jpg"})

    # Call the function
    result = screenshot_url_command(mock_client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "SilentPush.Screenshot"
    assert result.outputs_key_field == "url"
    assert result.outputs["url"] == "https://example.com"
    assert result.outputs["status"] == "success"
    assert result.outputs["screenshot_url"] == "https://example.com/screenshot.jpg"
    assert "Screenshot captured for https://example.com" in result.readable_output


def test_screenshot_url_command_no_url(mock_client):
    # Mock arguments without URL
    args = {}

    # Call the function and expect ValueError
    with pytest.raises(ValueError, match="URL is required"):
        screenshot_url_command(mock_client, args)


def test_screenshot_url_command_error_from_api(mock_client):
    # Mock arguments
    args = {
        "url": "https://example.com"
    }

    # Mock response from client with error
    mock_response = {
        "error": "Invalid URL"
    }
    mock_client.screenshot_url.return_value = mock_response

    # Call the function and expect Exception
    with pytest.raises(Exception, match="Invalid URL"):
        screenshot_url_command(mock_client, args)


def test_screenshot_url_command_failed_image_download(mock_client, mocker):
    # Mock arguments
    args = {
        "url": "https://example.com"
    }

    # Mock response from client
    mock_response = {
        "screenshot_url": "https://example.com/screenshot.jpg",
        "status_code": 200
    }
    mock_client.screenshot_url.return_value = mock_response

    # Mock requests.get with failed status code
    mock_image_response = mocker.Mock(spec=Response)
    mock_image_response.status_code = 404
    mocker.patch("requests.get", return_value=mock_image_response)

    # Call the function
    result = screenshot_url_command(mock_client, args)

    # Assertions
    assert result["error"] == "Failed to download screenshot image: HTTP 404"


def test_live_url_scan_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "url": "https://example.com",
        "platform": "Desktop",
        "os": "Windows",
        "browser": "Chrome",
        "region": "US"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "scan": {
                "status": "completed",
                "details": "Scan completed successfully",
                "screenshot_url": "https://example.com/screenshot.jpg"
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
        "region": "invalid_region"
    }

    # Mock validate_parameters to return validation errors
    mocker.patch("SilentPush.validate_parameters", return_value="Invalid parameters provided")

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="Invalid parameters provided"):
        live_url_scan_command(mock_client, args)


def test_live_url_scan_command_no_scan_results(mock_client, mocker):
    # Mock arguments
    args = {
        "url": "https://example.com",
        "platform": "Desktop",
        "os": "Windows",
        "browser": "Chrome",
        "region": "US"
    }

    # Mock response from client with no scan results
    mock_response = {
        "response": {
            "scan": {}
        }
    }
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
    args = {
        "query": "domain:example.com"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "scandata_raw": [
                {"domain": "example.com", "ip": "192.168.1.1", "status": "active"},
                {"domain": "example.org", "ip": "192.168.1.2", "status": "inactive"}
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
    args = {
        "query": "domain:example.com"
    }

    # Mock response from client with no data
    mock_response = {
        "response": {
            "scandata_raw": []
        }
    }
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
    args = {
        "qtype": "A",
        "qname": "example.com"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "records": [
                {"answer": "192.168.1.1", "type": "A", "ttl": 3600},
                {"answer": "192.168.1.2", "type": "A", "ttl": 3600}
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
    args = {
        "qtype": "A",
        "qname": "example.com"
    }

    # Mock response from client with no records
    mock_response = {
        "response": {
            "records": []
        }
    }
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
    args = {
        "qtype": "A",
        "qname": "example.com"
    }

    # Mock response from client with an error
    mock_response = {
        "error": "Invalid query"
    }
    mock_client.reverse_padns_lookup.return_value = mock_response

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="API Error: Invalid query"):
        reverse_padns_lookup_command(mock_client, args)


def test_forward_padns_lookup_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "qtype": "A",
        "qname": "example.com",
        "limit": "10"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "records": [
                {"answer": "192.168.1.1", "type": "A", "ttl": 3600},
                {"answer": "192.168.1.2", "type": "A", "ttl": 3600}
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
    args = {
        "qtype": "A",
        "qname": "example.com"
    }

    # Mock response from client with no records
    mock_response = {
        "response": {
            "records": []
        }
    }
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
    args = {
        "qtype": "A",
        "qname": "example.com"
    }

    # Mock response from client with an error
    mock_response = {
        "error": "Invalid query"
    }
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
        "limit": "5"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "records": [
                {"domain": "example.com", "risk_score": 85, "registrar": "Example Registrar"},
                {"domain": "example.org", "risk_score": 70, "registrar": "Another Registrar"}
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
    args = {
        "domain": "nonexistent.com",
        "limit": "5"
    }

    # Mock response from client with no records
    mock_response = {
        "response": {
            "records": []
        }
    }
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
    args = {
        "risk_score_min": "invalid",
        "risk_score_max": "invalid"
    }

    # Call the function and expect ValueError
    with pytest.raises(ValueError):
        search_domains_command(mock_client, args)


def test_density_lookup_command_success(mock_client, mocker):
    # Mock arguments
    args = {
        "qtype": "nssrv",
        "query": "example.com",
        "scope": "global"
    }

    # Mock response from client
    mock_response = {
        "response": {
            "records": [
                {"name": "ns1.example.com", "density": 10},
                {"name": "ns2.example.com", "density": 5}
            ]
        }
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
    args = {
        "qtype": "nssrv",
        "query": "nonexistent.com"
    }

    # Mock response from client with no records
    mock_response = {
        "response": {
            "records": []
        }
    }
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
    args = {
        "qtype": "nssrv",
        "query": "example.com"
    }

    # Mock response from client with an error
    mock_response = {
        "error": "Invalid query"
    }
    mock_client.density_lookup.return_value = mock_response

    # Call the function and expect DemistoException
    with pytest.raises(DemistoException, match="API Error: Invalid query"):
        density_lookup_command(mock_client, args)
