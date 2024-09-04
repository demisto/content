import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import AdoptionMetrics
import pytest


CASES_CHECK_PHISHING = [
    ([], False),  # incidents_not_exists
    (["Phishing"], True)  # phishing incident found
]


@pytest.mark.parametrize('data, expected_result', CASES_CHECK_PHISHING)
def test_check_phishing_incidents(mocker, data, expected_result):
    """
    Given:
        case1 = No incidents fetched from Demisto.
        case2 = Phishing incident found in fetched incidents.

    When:
        - Checking for phishing incidents.

    Then:
        - Assert the result returned is as expected.
    """
    # Simulate no incidents fetched
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Contents": {"data": data}}]
    )
    assert AdoptionMetrics.check_phishing_incidents() == expected_result


CASES_RAPID_BREACH_RESPONSE = [
    ([{"Contents": {"response": []}, "Type": EntryType.NOTE}], False),  # No content packs are installed.
    # content packs are installed.
    ([{"Contents": {"response": [{"name": "Rapid Breach Response"}]}, "Type": EntryType.NOTE}], True)
]


@pytest.mark.parametrize('return_value, expected_result', CASES_RAPID_BREACH_RESPONSE)
def test_is_rapid_breach_response_installed(mocker, return_value, expected_result):
    """
    Given:
        case1 = No content packs are installed.
        case2 = content packs are installed.

    When:
        - Checking if Rapid Breach Response is installed.

    Then:
        - Assert the result returned is as expected
    """
    # Simulate no content packs installed
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=return_value
    )

    assert AdoptionMetrics.is_rapid_breach_response_installed() == expected_result


def test_get_use_cases(mocker):
    """
    Given:
        - Various modules with different categories and states.
        - No phishing incidents fetched.
        - Rapid Breach Response not installed.
    When:
        - Retrieving use cases data.
    Then:
        - Use cases in production and at risk are returned correctly.
    """
    from AdoptionMetrics import get_use_cases
    # Simulate modules with different categories and states
    mocker.patch.object(demisto, "getModules", return_value={
        '1': {'category': 'case management', 'brand': 'Brand', 'state': 'active'},
        '2': {'category': 'Email', 'brand': 'Brand', 'state': 'active', 'incident_types': ['Phishing']},
        '3': {'category': 'network security', 'brand': 'Brand', 'state': 'active'},
        '4': {'category': 'vulnerability management', 'brand': 'Brand', 'state': 'at_risk'}
    })
    link = 'https://cortex.marketplace.pan.dev/marketplace/'
    mocker.patch.object(AdoptionMetrics, 'check_phishing_incidents', return_value=False)
    mocker.patch.object(AdoptionMetrics, 'is_rapid_breach_response_installed', return_value=False)
    res = get_use_cases()
    assert res == {'use_cases_in_production': {'Case Management', 'Network Security'},
                   'at_risk': {'Ransomware & Malware Coverage': f'{link}?useCase=Malware',
                               'Business Email Compromise Coverage': f'{link}?useCase=Phishing',
                               'Analytics & SIEM': f'{link}?category=Analytics+%26+SIEM',
                               'Data Enrichment & Threat Intelligence':
                                   f'{link}?category=Data+Enrichment+%26+Threat+Intelligence',
                               'Vulnerability Management':
                                   'https://xsoar.pan.dev/marketplace/?category=Vulnerability%20Management',
                               'Rapid Breach Response':
                                   f'{link}details/MajorBreachesInvestigationandResponse/'}}


def test_main(mocker):
    """
    Given:
        - Use cases data.

    When:
        - Generating Markdown table.

    Then:
        - Markdown table is generated correctly.
    """
    import AdoptionMetrics
    use_cases_data = {
        'use_cases_in_production': {'Ransomware & Malware Coverage', 'Network Security'},
        'at_risk': {'Business Email Compromise Coverage': 'https://xsoar.pan.dev/marketplace/?category=Email%2C%20Messaging'}
    }
    mocker.patch.object(AdoptionMetrics, 'get_use_cases', return_value=use_cases_data)
    res = AdoptionMetrics.main()
    assert '| Network Security | ✅ |' in res
    assert 'Business Email Compromise Coverage | ❌ |' in res
    assert 'Rapid Breach Response' not in res
