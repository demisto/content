import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def check_phishing_incidents() -> bool | DemistoException:
    """
    Checks for phishing incidents.

    Returns:
        bool: True if phishing incidents are found, False otherwise.
    """
    try:
        res = demisto.executeCommand("getIncidents", {"type": "Phishing", "size": 1})
        return bool(res and res[0].get("Contents", {}).get("data"))
    except DemistoException as e:
        return DemistoException(str(e))


def is_rapid_breach_response_installed() -> bool | DemistoException:
    """
    Checks if Rapid Breach Response is installed.

    Returns:
        bool: True if Rapid Breach Response is installed, False otherwise.
    """
    try:
        res = demisto.executeCommand("core-api-get", {"uri": "/contentpacks/metadata/installed"})
        if res:
            for entry in res:
                if is_error(entry):
                    return_error(get_error(entry))
            installed_packs = res[0].get("Contents", {}).get("response")
            return any(pack["name"] == "Rapid Breach Response" for pack in installed_packs)
        return False
    except DemistoException as e:
        return DemistoException(str(e))


def get_use_cases() -> Dict[str, Any]:
    """
    Retrieves use cases data based on modules in Demisto.

    Returns:
        dict: A dictionary containing use cases in production and at risk.
    """
    use_cases_in_production = set()
    at_risk = []

    phishing_incidents = check_phishing_incidents()
    use_case_dict = {
        'Ransomware & Malware Coverage': 'https://cortex.marketplace.pan.dev/marketplace/?useCase=Malware',
        'Business Email Compromise Coverage': 'https://cortex.marketplace.pan.dev/marketplace/?useCase=Phishing',
        'Network Security': 'https://xsoar.pan.dev/marketplace/?category=Network%20Security',
        'Analytics & SIEM': 'https://cortex.marketplace.pan.dev/marketplace/?category=Analytics+%26+SIEM',
        'Data Enrichment & Threat Intelligence':
            'https://cortex.marketplace.pan.dev/marketplace/?category=Data+Enrichment+%26+Threat+Intelligence',
        'Vulnerability Management': 'https://xsoar.pan.dev/marketplace/?category=Vulnerability%20Management',
        'Case Management': 'https://cortex.marketplace.pan.dev/marketplace/?category=Case+Management',
        'Rapid Breach Response': 'https://cortex.marketplace.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse/'
    }

    catagories = {
        'network security': 'Network Security',
        'analytics & siem': 'Analytics & SIEM',
        'data enrichment & threat intelligence': 'Data Enrichment & Threat Intelligence',
        'vulnerability management': 'Vulnerability Management',
        'case management': 'Case Management',
        'forensic & malware analysis': 'Ransomware & Malware Coverage',
        'endpoint': 'Ransomware & Malware Coverage'
    }

    for _, details in demisto.getModules().items():
        category = details.get('category', '').lower()
        brand = details.get('brand', '').lower()
        state = details.get('state')

        if brand != 'builtin' and state == 'active' and category != 'utilities':
            if category in ['email', 'messaging', 'messaging and conferencing']:
                if phishing_incidents:
                    use_cases_in_production.add('Business Email Compromise Coverage')
                else:
                    at_risk.append(
                        '[Business Email Compromise Coverage](https://xsoar.pan.dev/marketplace/?category=Email%2C%20Messaging)')
            elif category in catagories:
                use_cases_in_production.add(catagories[category])

    if is_rapid_breach_response_installed():
        use_cases_in_production.add('Rapid Breach Response')

    at_risk_dict = {}
    for use_case, url in use_case_dict.items():
        if use_case not in use_cases_in_production:
            at_risk_dict[use_case] = url

    return {
        'use_cases_in_production': use_cases_in_production,
        'at_risk': at_risk_dict
    }


def main():
    use_cases_data = get_use_cases()

    headers = ['Use Case Adoption & Coverage', 'Status']
    t = []
    for use_case in use_cases_data['use_cases_in_production']:
        t.append({'Use Case Adoption & Coverage': use_case, 'Status': '✅'})

    for use_case, _ in use_cases_data['at_risk'].items():
        t.append({'Use Case Adoption & Coverage': use_case, 'Status': '❌'})
    table = tableToMarkdown(name='Use Case Coverage', t=t, headers=headers)

    return_results(table)
    return table


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
