import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def check_phishing_incidents():
    try:
        res = demisto.executeCommand("getIncidents", {"type": "Phishing", "size": 1})
        if res:
            incidents = res[0].get("Contents", {}).get("data")
            return bool(incidents)
    except DemistoException as e:
        return DemistoException(str(e))


def is_rapid_breach_response_installed():
    try:
        res = demisto.executeCommand("core-api-get", {"uri": "/contentpacks/metadata/installed"})
        if res:
            installed_packs = res[0].get("Contents", {}).get("response")
            return any(pack["name"] == "Rapid Breach Response" for pack in installed_packs)
    except DemistoException as e:
        return DemistoException(str(e))


def get_use_cases():
    use_cases_in_production = set()
    at_risk = []

    phishing_incidents = check_phishing_incidents()
    use_case_dict = {
        'Ransomware & Malware Coverage': 'https://cortex.marketplace.pan.dev/marketplace/?useCase=Malware',
        'Business Email Compromise Coverage': 'https://cortex.marketplace.pan.dev/marketplace/?useCase=Phishing',
        'Network Security': 'https://xsoar.pan.dev/marketplace/?category=Network%20Security',
        'Analytics & SIEM': 'https://cortex.marketplace.pan.dev/marketplace/?category=Analytics+%26+SIEM',
        'Data Enrichment & Threat Intelligence': 'https://cortex.marketplace.pan.dev/marketplace/?category=Data+Enrichment+%26+Threat+Intelligence',
        'Vulnerability Management': 'https://xsoar.pan.dev/marketplace/?category=Vulnerability%20Management',
        'Case Management': 'https://cortex.marketplace.pan.dev/marketplace/?category=Case+Management',
        'Rapid Breach Response': 'https://cortex.marketplace.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse/'
    }

    for _, details in demisto.getModules().items():
        category = details.get('category', '').lower()
        brand = details.get('brand', '').lower()
        state = details.get('state')
        incident_types = details.get('incident_types', [])

        if brand != 'builtin' and state == 'active' and category != 'utilities':
            if category in ['forensic & malware analysis', 'endpoint']:
                use_cases_in_production.add('Ransomware & Malware Coverage')
            elif category in ['email', 'messaging', 'messaging and conferencing'] and 'phishing' in incident_types:
                if phishing_incidents:
                    use_cases_in_production.add('Business Email Compromise Coverage')
                else:
                    at_risk.append('[Business Email Compromise Coverage](https://xsoar.pan.dev/marketplace/?category=Email%2C%20Messaging)')
            elif category == 'network security':
                use_cases_in_production.add('Network Security')
            elif category == 'analytics & siem':
                use_cases_in_production.add('Analytics & SIEM')
            elif category == 'data enrichment & threat intelligence':
                use_cases_in_production.add('Data Enrichment & Threat Intelligence')
            elif category == 'vulnerability management':
                use_cases_in_production.add('Vulnerability Management')
            elif category == 'case management':
                use_cases_in_production.add('Case Management')

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
        t.append([use_case, '✅'])

    for use_case, url in use_cases_data['at_risk'].items():
        t.append([f'[{use_case}]({url})', '❌'])
    table = tableToMarkdown(name='Use Case Coverage', t=t, headers=headers)

    return return_results(table)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()