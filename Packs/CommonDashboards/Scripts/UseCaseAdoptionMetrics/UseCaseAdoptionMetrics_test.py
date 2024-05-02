import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import UseCaseAdoptionMetrics


def test_check_phishing_incidents_incidents_not_exists(mocker):
    """
    Given:
        - No incidents fetched from Demisto.

    When:
        - Checking for phishing incidents.

    Then:
        - No incidents are found.
    """
    # Simulate no incidents fetched
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Contents": {"data": []}}]
    )
    assert not UseCaseAdoptionMetrics.check_phishing_incidents()


def test_check_phishing_incidents(mocker):
    """
    Given:
        - Incidents fetched from Demisto.

    When:
        - Checking for phishing incidents.

    Then:
        - Returns True.
    """
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Contents": {"data": ['check']}}]
    )
    assert UseCaseAdoptionMetrics.check_phishing_incidents()


def test_is_rapid_breach_response_installed_packs_not_installed(mocker):
    """
    Given:
        - No content packs are installed.

    When:
        - Checking if Rapid Breach Response is installed.

    Then:
        - Returns False.
    """
    # Simulate no content packs installed
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Contents": {"response": []}}]
    )

    assert not UseCaseAdoptionMetrics.is_rapid_breach_response_installed()


def test_is_rapid_breach_response_installed(mocker):
    """
    Given:
        - No content packs are installed.

    When:
        - Checking if Rapid Breach Response is installed.

    Then:
        - Returns True.
    """
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Contents": {"response": [{"name": "Rapid Breach Response"}]}}]
    )
    assert UseCaseAdoptionMetrics.is_rapid_breach_response_installed()


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
    from UseCaseAdoptionMetrics import get_use_cases
    # Simulate modules with different categories and states
    mocker.patch.object(demisto, "getModules", return_value={
        '1': {'category': 'case management', 'brand': 'Brand', 'state': 'active'},
        '2': {'category': 'Email', 'brand': 'Brand', 'state': 'active', 'incident_types': ['Phishing']},
        '3': {'category': 'network security', 'brand': 'Brand', 'state': 'active'},
        '4': {'category': 'vulnerability management', 'brand': 'Brand', 'state': 'at_risk'}
    })
    link = 'https://cortex.marketplace.pan.dev/marketplace/'
    mocker.patch.object(UseCaseAdoptionMetrics, 'check_phishing_incidents', return_value=False)
    mocker.patch.object(UseCaseAdoptionMetrics, 'is_rapid_breach_response_installed', return_value=False)
    res = get_use_cases()
    assert res == {'use_cases_in_production': {'Case Management', 'Network Security'},
                   'at_risk': {'Ransomware & Malware Coverage': f'{link}?useCase=Malware',
                               'Business Email Compromise Coverage': f'{link}?useCase=Phishing',
                               'Analytics & SIEM': f'{link}?category=Analytics+%26+SIEM',
                               'Data Enrichment & Threat Intelligence': f'{link}?category=Data+Enrichment+%26+Threat+Intelligence',
                               'Vulnerability Management': 'https://xsoar.pan.dev/marketplace/?category=Vulnerability%20Management',
                               'Rapid Breach Response': f'{link}details/MajorBreachesInvestigationandResponse/'}}


def test_main(mocker):
    """
    Given:
        - Use cases data.

    When:
        - Generating Markdown table.

    Then:
        - Markdown table is generated correctly.
    """
    import UseCaseAdoptionMetrics
    use_cases_data = {
        'use_cases_in_production': {'Ransomware & Malware Coverage', 'Network Security'},
        'at_risk': {'Business Email Compromise Coverage': 'https://xsoar.pan.dev/marketplace/?category=Email%2C%20Messaging'}
    }
    expected_table = '### Use Case Coverage\n|Use Case Adoption & Coverage|Status|\n|---|---|\n' \
        '| Ransomware & Malware Coverage | ✅ |\n| Network Security | ✅ |\n| Business Email Compromise Coverage | ❌ |\n'
    mocker.patch.object(UseCaseAdoptionMetrics, 'get_use_cases', return_value=use_cases_data)
    res = UseCaseAdoptionMetrics.main()
    assert res == expected_table
