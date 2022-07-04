import pytest
import MicrosoftGraphIdentityandAccess

ipv4 = {'@odata.type': '#microsoft.graph.iPv4CidrRange', 'cidrAddress': '12.34.221.11/22'}  # noqa
ipv6 = {'@odata.type': '#microsoft.graph.iPv6CidrRange', 'cidrAddress': '2001:0:9d38:90d6:0:0:0:0/63'}  # noqa


@pytest.mark.parametrize("ips,expected", [("12.34.221.11/22,2001:0:9d38:90d6:0:0:0:0/63", [ipv4, ipv6]),
                                          ("12.34.221.11/22,12.34.221.11/22", [ipv4, ipv4]),
                                          ("2001:0:9d38:90d6:0:0:0:0/63,2001:0:9d38:90d6:0:0:0:0/63", [ipv6, ipv6])])
def test_ms_ip_string_to_list(ips, expected):
    """
    Given:
    -   Ips in a string

    When:
    -   Convetting them to an ip list.

    Then:
    - Ensure that the list we get is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.ms_ip_string_to_list(ips) == expected


@pytest.mark.parametrize("last,expected", [({'latest_detection_found': '2022-06-06'}, '2022-06-06')])
def test_get_last_fetch_time(last, expected):
    """
    Given:
    -   A dict with the last run details.

    When:
    -  Getting the last run time value.

    Then:
    - Ensure that the time is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.get_last_fetch_time(last, {}) == expected


@pytest.mark.parametrize("date,expected", [('2022-06-06', '2022-06-06.000')])
def test_date_str_to_azure_format(date, expected):
    """
    Given:
    -   A date to convert to Azure format.

    When:
    -  Converting the date value.

    Then:
    - Ensure that the date is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.date_str_to_azure_format(date) == expected


@pytest.mark.parametrize("incident,expected",
                         [({}, {'name': 'Azure AD:   ', 'occurred': '2022-06-06Z', 'rawJSON': '{}'}),
                          ({'riskEventType': '3', 'riskDetail': '2', 'id': '1'},
                           {'name': 'Azure AD: 1 3 2',
                            'occurred': '2022-06-06Z',
                            'rawJSON': '{"riskEventType": "3", "riskDetail": "2", "id": "1"}'})
                          ])
def test_detection_to_incident(incident, expected):
    """
    Given:
    -  A dict with the incident details.

    When:
    -  Getting the incident.

    Then:
    - Ensure that the dict is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.detection_to_incident(incident, '2022-06-06') == expected


@pytest.mark.parametrize("last_fetch,expected", [('2022-06-06', 'detectedDateTime gt 2022-06-06')])
def test_build_filter(last_fetch, expected):
    """
    Given:
    -   A date to set a filter by.

    When:
    -  Doing an odata query.

    Then:
    - Ensure that the filter is what we expected.
    """

    assert MicrosoftGraphIdentityandAccess.build_filter(last_fetch, {}) == expected
