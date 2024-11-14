"""
Tests module for Xpanse Feed integration.
"""

# Client for multiple tests
from FeedXpanse import Client
client = Client(
    base_url='https://test.com', tlp_color="GREEN",
    verify=True, feed_tags=["test_tag"],
    headers={
        "HOST": "test.com",
        "Authorizatio": "THISISAFAKEKEY",
        "Content-Type": "application/json"
    },
    proxy=False)


def test_map_indicator_type():
    """Tests map_indicator_type helper function.

        Given:
            - Indicator type input
        When:
            - Getting output from map_indicator_type helper function
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from FeedXpanse import map_indicator_type
    # Test know types
    assert map_indicator_type('UNASSOCIATED_RESPONSIVE_IP') == 'IP'
    assert map_indicator_type('DOMAIN') == 'Domain'
    assert map_indicator_type('CERTIFICATE') == 'X509 Certificate'
    assert map_indicator_type('CIDR') == 'CIDR'
    # test_map_unknown_type
    assert map_indicator_type('UNKNOWN_TYPE') == 'None'
    # test_map_empty_string
    assert map_indicator_type('') == 'None'
    # test_map_none_input
    assert map_indicator_type('domain') == 'None'


def test_create_x509_certificate_grids():
    """Tests create_x509_certificate_grids helper function.

        Given:
            - Indicator type input
        When:
            - Getting output from create_x509_certificate_grids helper function
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from FeedXpanse import create_x509_certificate_grids
    # test_with_valid_string
    input_str = "C=ZA,ST=Western Cape,L=Cape Town,O=Thawte"
    expected_output = [
        {"title": "C", "data": "ZA"},
        {"title": "ST", "data": "Western Cape"},
        {"title": "L", "data": "Cape Town"},
        {"title": "O", "data": "Thawte"}
    ]
    assert create_x509_certificate_grids(input_str) == expected_output

    # test_with_none_input
    assert create_x509_certificate_grids(None) == []

    # test_with_empty_string
    assert create_x509_certificate_grids('') == []


def test_map_indicator_fields():
    """Tests map_indicator_fields helper function.

        Given:
            - Indicator type input
        When:
            - Getting output from map_indicator_fields helper function
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from FeedXpanse import map_indicator_fields
    # test_map_indicator_fields_domain
    raw_indicator = {
        "name": "example.com",
        "domain_details": {
            "creationDate": 1609459200,
            "registryExpiryDate": 1609459200,
        }
    }
    asset_type = 'Domain'
    expected_output = {
        "internal": True,
        "description": "example.com indicator of asset type Domain from Cortex Xpanse",
        "creationdate": '1970-01-19T15:04:19.000Z',
        "expirationdate": '1970-01-19T15:04:19.000Z'
    }
    assert map_indicator_fields(raw_indicator, asset_type) == expected_output

    # test_map_indicator_fields_x509_certificate
    raw_indicator = {
        "name": "certificate",
        "certificate_details": {
            "signatureAlgorithm": "SHA256WithRSAEncryption",
            "serialNumber": "1234567890",
            "validNotAfter": 1609459200,
            "validNotBefore": 1609459200,
            "issuer": "C=US,ST=California",
            "subject": "C=US,ST=California",
        }
    }
    asset_type = 'X509 Certificate'
    expected_output = {
        "internal": True,
        "description": "certificate indicator of asset type X509 Certificate from Cortex Xpanse",
        "signaturealgorithm": "SHA256WithRSAEncryption",
        "serialnumber": "1234567890",
        "validitynotafter": "1970-01-19T15:04:19.000Z",
        "validitynotbefore": "1970-01-19T15:04:19.000Z",
        "issuer": [{"title": "C", "data": "US"}, {"title": "ST", "data": "California"}],
        "subject": [{"title": "C", "data": "US"}, {"title": "ST", "data": "California"}]
    }
    assert map_indicator_fields(raw_indicator, asset_type) == expected_output


def test_build_asset_indicators():
    """Tests build_asset_indicators helper function.

        Given:
            - Indicator type input
        When:
            - Getting output from build_asset_indicators helper function
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from FeedXpanse import build_asset_indicators
    # test_build_asset_indicators
    raw_indicators = [
        {"name": "example.com", "asset_type": "DOMAIN"},
        {"name": "example.net", "asset_type": "DOMAIN", "ipv6s": ["::1"]},  # This should be skipped
        {"name": "*.example.org", "asset_type": "DOMAIN"},  # This should become a DomainGlob
        {"name": "nonexistent", "asset_type": "CLOUD_SERVER"},  # This should be skipped
    ]
    expected_output = [
        {
            'value': "example.com",
            'type': "Domain",
            'fields': {
                "internal": True,
                "description": "example.com indicator of asset type Domain from Cortex Xpanse",
                "trafficlightprotocol": "GREEN",
                "tags": ["test_tag"]
            },
            'rawJSON': {"name": "example.com", "asset_type": "DOMAIN"}
        },
        {
            'value': "*.example.org",
            'type': "DomainGlob",
            'fields': {
                "internal": True,
                "description": "*.example.org indicator of asset type DomainGlob from Cortex Xpanse",
                "trafficlightprotocol": "GREEN",
                "tags": ["test_tag"]
            },
            'rawJSON': {"name": "*.example.org", "asset_type": "DOMAIN"}
        }
    ]
    assert build_asset_indicators(client, raw_indicators) == expected_output


def test_fetch_indicators(mocker):
    """Tests fetch_indicators command function.

        Given:
            - requests_mock instance to generate the appropriate list_asset_internet_exposure_command( API response,
              loaded from a local JSON file.
        When:
            - Getting output from fetch_indicators command function
        Then:
            - Checks the output of the command function with the expected output.
    """
    from FeedXpanse import fetch_indicators
    from test_data.raw_response import EXTERNAL_EXPOSURES_RESPONSE
    mocker.patch.object(client, 'list_asset_internet_exposure_request', return_value=EXTERNAL_EXPOSURES_RESPONSE)
    indicators, _ = fetch_indicators(client, limit=1, asset_type='domain')
    expected_indicators_fields = {
        "internal": True,
        "description": "example.com indicator of asset type Domain from Cortex Xpanse",
        "trafficlightprotocol": "GREEN",
        "tags": ["test_tag"],
    }
    assert indicators[0]['fields'] == expected_indicators_fields


def test_get_indicators(mocker):
    """Tests get_indicators command function.

        Given:
            - requests_mock instance to generate the appropriate list_asset_internet_exposure_command( API response,
              loaded from a local JSON file.
        When:
            - Getting output from get_indicators command function
        Then:
            - Checks the output of the command function with the expected output.
    """
    from FeedXpanse import get_indicators
    from test_data.raw_response import EXTERNAL_EXPOSURES_RESPONSE
    mocker.patch.object(client, 'list_asset_internet_exposure_request', return_value=EXTERNAL_EXPOSURES_RESPONSE)
    args = {"limit": "1", 'domain': "yes", "certificate": "no", "ipv4": "no"}
    response = get_indicators(client, args)
    assert response.outputs[0]['Type'] == 'Domain'
