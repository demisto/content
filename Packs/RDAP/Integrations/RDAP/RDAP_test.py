import pytest
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from RDAP import RDAPClient, parse_ip_response, parse_domain_response, parse_indicator_data
from requests.exceptions import RequestException


@pytest.fixture
def client():
    return RDAPClient(base_url='https://rdap.org', verify=False)


def test_parse_indicator_data():
    # Test IP case
    ip_input = "8.8.8.8"
    ip_response = {"ipVersion": "v4"}
    ip_result, ip_context, ip_readable = parse_indicator_data(ip_input, "ip", ip_response)

    assert isinstance(ip_result, Common.IP)
    assert ip_result.ip == "8.8.8.8"
    assert ip_context['Value'] == "8.8.8.8"
    assert ip_context['IndicatorType'] == "IP"

    # Test Domain case
    domain_input = "example.com"
    domain_response = {}
    domain_result, domain_context, domain_readable = parse_indicator_data(domain_input, "domain", domain_response)

    assert isinstance(domain_result, Common.Domain)
    assert domain_result.domain == "example.com"
    assert domain_context['Value'] == "example.com"
    assert domain_context['IndicatorType'] == "Domain"

    # Test unsupported indicator type
    with pytest.raises(TypeError):
        parse_indicator_data("test", "unsupported", {})


def test_parse_domain_response():
    indicator = "example.com"
    response = {
        "events": [
            {"eventAction": "registration", "eventDate": "2021-01-01"},
            {"eventAction": "expiration", "eventDate": "2022-01-01"},
            {"eventAction": "last changed", "eventDate": "2021-06-01"}
        ],
        "secureDNS": {"delegationSigned": True}
    }
    domain, context, readable_output = parse_domain_response(indicator, response)

    assert domain.creation_date == "2021-01-01"
    assert domain.expiration_date == "2022-01-01"

    assert context == {
        'Value': indicator,
        'IndicatorType': 'Domain',
        'RegistrationDate': '2021-01-01',
        'ExpirationDate': '2022-01-01',
        'LastChangedDate': '2021-06-01',
        'SecureDNS': True
    }

    assert readable_output == tableToMarkdown(
        f'RDAP Information for {indicator}',
        [
            {'Field': 'Registration Date', 'Value': '2021-01-01'},
            {'Field': 'Expiration Date', 'Value': '2022-01-01'},
            {'Field': 'Secure DNS', 'Value': True}
        ]
    )


def test_parse_ip_response():
    indicator = "8.8.8.8"
    response = {
        "ipVersion": "v4",
        "country": "US",
        "remarks": [
            {"title": "description", "description": ["Google Public DNS"]}
        ],
        "entities": [
            {
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [
                        ["adr", {"label": "1600 Amphitheatre Parkway, Mountain View, CA, 94043, US"},
                            "text", ["", "", "", "", "", "", ""]],
                        ["fn", {}, "text", "Google LLC"],
                        ["email", {}, "text", "abuse@google.com"],
                        ["tel", {}, "uri", "+16502530000"]
                    ]
                ]
            }
        ]
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
        f'RDAP Information for {indicator}',
        [
            {"Field": "Abuse Address", "Value": "1600 Amphitheatre Parkway, Mountain View, CA, 94043, US"},
            {"Field": "Abuse Name", "Value": "Google LLC"},
            {"Field": "Abuse Email", "Value": "abuse@google.com"}
        ]
    )


def test_main(mocker):
    import RDAP

    mocker.patch.object(demisto, 'args', return_value={'domain': 'example.com'})
    mocker.patch.object(demisto, 'command', return_value='domain')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(RDAPClient, 'rdap_query', return_value={
        "events": [
            {"eventAction": "registration", "eventDate": "2021-01-01"},
            {"eventAction": "expiration", "eventDate": "2022-01-01"},
            {"eventAction": "last changed", "eventDate": "2021-06-01"}
        ],
        "secureDNS": {"delegationSigned": True}
    })

    RDAP.main()

    assert demisto.results.called
    demisto.results.reset_mock()

    # Test 404 response
    mocker.patch.object(demisto, 'args', return_value={'domain': 'nonexistent.com'})
    mocker.patch.object(RDAPClient, 'rdap_query', side_effect=RequestException(response=mocker.Mock(status_code=404)))

    RDAP.main()

    assert demisto.results.called
    result = demisto.results.call_args[0][0]
    assert "Indicator Not Found" in result['HumanReadable']
