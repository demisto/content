import pytest
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from RDAP import RDAPClient, parse_ip_response, parse_domain_response, build_results
from requests.exceptions import RequestException


@pytest.fixture
def client():
    return RDAPClient(base_url="https://rdap.org", verify=False)


def test_parse_domain_response():
    indicator = "example.com"
    response = {
        "events": [
            {"eventAction": "registration", "eventDate": "2021-01-01"},
            {"eventAction": "expiration", "eventDate": "2022-01-01"},
            {"eventAction": "last changed", "eventDate": "2021-06-01"},
        ],
        "secureDNS": {"delegationSigned": True},
    }
    domain, context, readable_output = parse_domain_response(indicator, response)

    assert domain.creation_date == "2021-01-01"
    assert domain.expiration_date == "2022-01-01"

    assert context == {
        "Value": indicator,
        "IndicatorType": "Domain",
        "RegistrationDate": "2021-01-01",
        "ExpirationDate": "2022-01-01",
        "LastChangedDate": "2021-06-01",
        "SecureDNS": "True",
    }

    assert readable_output == tableToMarkdown(
        f"RDAP Information for {indicator}",
        [
            {"Field": "Registration Date", "Value": "2021-01-01"},
            {"Field": "Expiration Date", "Value": "2022-01-01"},
            {"Field": "Secure DNS", "Value": True},
        ],
    )


def test_parse_ip_response():
    indicator = "8.8.8.8"
    response = {
        "ipVersion": "v4",
        "country": "US",
        "remarks": [{"title": "description", "description": ["Google Public DNS"]}],
        "entities": [
            {
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [
                        [
                            "adr",
                            {"label": "1600 Amphitheatre Parkway, Mountain View, CA, 94043, US"},
                            "text",
                            ["", "", "", "", "", "", ""],
                        ],
                        ["fn", {}, "text", "Google LLC"],
                        ["email", {}, "text", "abuse@google.com"],
                        ["tel", {}, "uri", "+16502530000"],
                    ],
                ],
            }
        ],
    }

    ip, context, readable_output = parse_ip_response(indicator, response)

    assert ip.ip_type == "IP"
    assert ip.geo_country == "US"
    assert ip.description == "Google Public DNS"
    assert ip.registrar_abuse_address == "1600 Amphitheatre Parkway, Mountain View, CA, 94043, US"
    assert ip.registrar_abuse_name == "Google LLC"

    assert context == {
        "Value": indicator,
        "IndicatorType": "IP",
        "RegistrarAbuseAddress": "1600 Amphitheatre Parkway, Mountain View, CA, 94043, US",
        "RegistrarAbuseName": "Google LLC",
        "RegistrarAbuseEmail": "abuse@google.com",
    }

    assert readable_output == tableToMarkdown(
        f"RDAP Information for {indicator}",
        [
            {"Field": "Abuse Address", "Value": "1600 Amphitheatre Parkway, Mountain View, CA, 94043, US"},
            {"Field": "Abuse Name", "Value": "Google LLC"},
            {"Field": "Abuse Email", "Value": "abuse@google.com"},
        ],
    )


def test_build_results(mocker):
    # Create mock client
    mock_client = mocker.Mock()
    mock_client.rdap_query.return_value = {
        "ipVersion": "v4",
        "country": "US",
        "remarks": [{"title": "description", "description": ["Test IP"]}],
        "entities": [
            {
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [
                        ["adr", {"label": "123 Test St, Test City, TC, 12345, US"}, "text", ["", "", "", "", "", "", ""]],
                        ["fn", {}, "text", "Test Corp"],
                        ["email", {}, "text", "abuse@test.com"],
                        ["tel", {}, "uri", "+15551234567"],
                    ],
                ],
            }
        ],
    }

    # Test basic functionality
    indicators = ["192.168.1.1", "192.168.0.1"]
    results = build_results(
        client=mock_client, parse_command=parse_ip_response, indicators=indicators, outputs_prefix="IP", command="ip"
    )

    # Verify results
    assert len(results) == 2
    assert mock_client.rdap_query.call_count == 2
    assert mock_client.rdap_query.call_args_list[0][1] == {"indicator_type": "ip", "value": "192.168.1.1"}
    assert mock_client.rdap_query.call_args_list[1][1] == {"indicator_type": "ip", "value": "192.168.0.1"}

    # Verify command results structure
    for i, result in enumerate(results):
        assert result.outputs_prefix == "RDAP.IP"
        assert result.outputs_key_field == "IP"
        assert result.outputs["Value"] == indicators[i]
        assert result.outputs["IndicatorType"] == "IP"
        assert result.indicator.ip == indicators[i]

    # Test handling of 404 errors
    mock_client.rdap_query.side_effect = requests.exceptions.RequestException(response=mocker.Mock(status_code=404))

    results = build_results(
        client=mock_client, parse_command=parse_ip_response, indicators=["192.168.0.1"], outputs_prefix="IP", command="ip"
    )

    assert len(results) == 1
    assert "Indicator Not Found" in results[0].readable_output

    # Test handling of other errors
    mock_error_response = mocker.Mock()
    mock_error_response.status_code = 500
    mock_error = requests.exceptions.RequestException(response=mock_error_response)
    mock_client.rdap_query.side_effect = mock_error

    with pytest.raises(requests.exceptions.RequestException) as excinfo:
        build_results(
            client=mock_client, parse_command=parse_ip_response, indicators=["192.168.0.1"], outputs_prefix="IP", command="ip"
        )

    # Verify that the exception raised is the same one we created
    assert excinfo.value == mock_error
    assert excinfo.value.response.status_code == 500


def test_main(mocker):
    import RDAP

    mocker.patch.object(demisto, "args", return_value={"domain": "example.com"})
    mocker.patch.object(demisto, "command", return_value="domain")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        RDAPClient,
        "rdap_query",
        return_value={
            "events": [
                {"eventAction": "registration", "eventDate": "2021-01-01"},
                {"eventAction": "expiration", "eventDate": "2022-01-01"},
                {"eventAction": "last changed", "eventDate": "2021-06-01"},
            ],
            "secureDNS": {"delegationSigned": True},
        },
    )

    RDAP.main()

    assert demisto.results.called
    demisto.results.reset_mock()

    # Test 404 response
    mocker.patch.object(demisto, "args", return_value={"domain": "nonexistent.com"})
    mocker.patch.object(RDAPClient, "rdap_query", side_effect=RequestException(response=mocker.Mock(status_code=404)))

    RDAP.main()

    assert demisto.results.called
    result = demisto.results.call_args[0][0]
    assert "Indicator Not Found" in result["HumanReadable"]
