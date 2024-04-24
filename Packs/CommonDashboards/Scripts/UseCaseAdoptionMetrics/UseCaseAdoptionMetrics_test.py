import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from UseCaseAdoptionMetrics import check_phishing_incidents, main, is_rapid_breach_response_installed, get_use_cases


def test_check_phishing_incidents():
    """
    Given:
        - No incidents fetched from Demisto.

    When:
        - Checking for phishing incidents.

    Then:
        - No incidents are found.
    """
    # Simulate no incidents fetched
    demisto.executeCommand = lambda command, args: []

    assert not check_phishing_incidents()


def test_is_rapid_breach_response_installed():
    """
    Given:
        - No content packs are installed.

    When:
        - Checking if Rapid Breach Response is installed.

    Then:
        - Rapid Breach Response is not installed.
    """
    # Simulate no content packs installed
    demisto.executeCommand = lambda command, args: []

    assert not is_rapid_breach_response_installed()


def test_get_use_cases():
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
    # Simulate modules with different categories and states
    demisto.getModules = lambda: {
        '1': {'category': 'Forensic & Malware Analysis', 'brand': 'Brand', 'state': 'active'},
        '2': {'category': 'Email', 'brand': 'Brand', 'state': 'active', 'incident_types': ['Phishing']},
        '3': {'category': 'Network Security', 'brand': 'Brand', 'state': 'active'},
    }
    # Simulate no phishing incidents fetched
    demisto.executeCommand = lambda command, args: []
    # Simulate Rapid Breach Response not installed
    demisto.executeCommand = lambda command, args: []

    assert get_use_cases() == {'use_cases_in_production': {'Ransomware & Malware Coverage', 'Network Security'},
                               'at_risk': {'Business Email Compromise Coverage': 'https://xsoar.pan.dev/marketplace/?category=Email%2C%20Messaging'}}


def test_main():
    """
    Given:
        - Use cases data.

    When:
        - Generating Markdown table.

    Then:
        - Markdown table is generated correctly.
    """
    # Simulate use cases data
    use_cases_data = {
        'use_cases_in_production': {'Ransomware & Malware Coverage', 'Network Security'},
        'at_risk': {'Business Email Compromise Coverage': 'https://xsoar.pan.dev/marketplace/?category=Email%2C%20Messaging'}
    }
    # Simulate table generation
    tableToMarkdown = lambda name, t, headers: f"### {name}\n|{'|'.join(headers)}|\n|{'|'.join(['---'] * len(headers))}|\n" + \
                                               '\n'.join([f"|{'|'.join(row)}|" for row in t])

    assert main() == "### Use Case Coverage\n|Use Case Adoption & Coverage|Status|\n|---|---|\n|Ransomware & Malware Coverage|✅|\n|Network Security|✅|\n|[Business Email Compromise Coverage](https://xsoar.pan.dev/marketplace/?category=Email%2C%20Messaging)|❌|"

