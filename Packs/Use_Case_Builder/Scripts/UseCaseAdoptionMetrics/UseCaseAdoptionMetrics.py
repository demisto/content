import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Function to check if there is at least one incident with the "Phishing" type


def check_phishing_incidents():
    incident_type = "Phishing"
    res = demisto.executeCommand("getIncidents", {"type": incident_type, "size": 1})
    incidents = res[0]["Contents"]["data"]
    return bool(incidents)


def is_rapid_breach_response_installed():
    res = demisto.executeCommand("core-api-get", {"uri": "/contentpacks/metadata/installed"})
    installed_packs = res[0]["Contents"]["response"]
    return any(pack["name"] == "Rapid Breach Response" for pack in installed_packs)


modules = demisto.getModules()

use_cases_in_production = set()
at_risk = []

phishing_incidents = check_phishing_incidents()

for _module, details in modules.items():
    if details.get("brand").lower() != "builtin" and details.get('state') == 'active' and details.get('category') != 'Utilities':
        if details.get('category') in [
            'Forensic & Malware Analysis',
            'Endpoint'
        ]:
            use_cases_in_production.add('Ransomware & Malware Coverage')
        elif (
            details.get('category') in ['Email', 'Messaging', 'Messaging and Conferencing']
            and 'phishing' in details.get('incident_types', [])
        ):
            if phishing_incidents:
                use_cases_in_production.add('Business Email Compromise Coverage')
            else:
                at_risk.append(
                    '[Business Email Compromise Coverage](https://xsoar.pan.dev/marketplace/?category=Email%2C%20Messaging)'
                )
        elif details.get('category') == 'Network Security':
            use_cases_in_production.add('Network Security')
        elif details.get('category') == 'Analytics & SIEM':
            use_cases_in_production.add('Analytics & SIEM')
        elif details.get('category') == 'Data Enrichment & Threat Intelligence':
            use_cases_in_production.add('Data Enrichment & Threat Intelligence')
        elif details.get('category') == 'Vulnerability Management':
            use_cases_in_production.add('Vulnerability Management')
        elif details.get('category') == 'Case Management':
            use_cases_in_production.add('Case Management')

if is_rapid_breach_response_installed():
    use_cases_in_production.add('Rapid Breach Response')

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

for use_case, url in use_case_dict.items():
    if use_case not in use_cases_in_production:
        at_risk.append(f'[{use_case}]({url})')

table = "| Use Case Adoption & Coverage | Status |\n"
table += "|---|---|\n"
for use_case in use_cases_in_production:
    table += f"| {use_case} | &#x2705; |\n"

for use_case in at_risk:
    table += f"| {use_case} | &#x274c; |\n"

if at_risk:
    table += "\n"

demisto.results(table)
