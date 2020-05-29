from CommonServerPython import *

''' IMPORTS '''

from collections import defaultdict
from datetime import datetime, date
from typing import List, Dict, Any, DefaultDict

''' HELPER FUNCTION '''


def header_transform(key):
    """
    Function returns header key in human readable

    :param key: header key
    :return:
    """
    header_dict = {
        'Cve': 'CVE ID',
        'CVSS': 'CVSS Score',
        'VRR': 'VRR Score',
        'ThreatCount': 'Threat Count',
        'VulnLastTrendingOn': 'Last Trending On Date',
        'Trending': 'Trending',
    }

    return header_dict.get(key, '')


''' STANDALONE FUNCTION '''


def get_cve_list_from_host_findings(response):
    """
    Extract CVEs from host findings
    """

    host_findings = [response] if isinstance(response, dict) else response

    all_cves: DefaultDict[str, dict] = defaultdict(dict)

    for findings in host_findings:
        risk_rating = findings.get('RiskRating', 0)
        threat_list: DefaultDict[str, list] = defaultdict(list)

        if isinstance(response, dict):
            host_findings = [response]
        else:
            host_findings = response

        threats = findings.get('Threat') if findings.get('Threat', []) else []
        vulns = findings.get('Vulnerability') if findings.get('Vulnerability', []) else []

        # if dict response receive from context data then convert it to list
        threats = [threats] if isinstance(threats, dict) else threats
        vulns = [vulns] if isinstance(vulns, dict) else vulns

        for threat in threats:
            for cve in threat.get('Cve', []):
                threat_list[cve].append({
                    'Title': threat.get('Title', ''),
                    'Category': threat.get('Category', ''),
                    'Severity': threat.get('Severity', ''),
                    'Description': threat.get('Description', ''),
                    'Cve': threat.get('Cve', ''),
                    'Source': threat.get('Source', ''),
                    'Published': threat.get('Published', ''),
                    'Updated': threat.get('Updated', ''),
                    'ThreatLastTrendingOn': threat.get('ThreatLastTrendingOn', ''),
                    'Trending': threat.get('Trending', '')
                })

        for vulnerability in vulns:
            last_trending = vulnerability.get('VulnLastTrendingOn', '')
            all_cves[vulnerability.get('Cve', 'No ID Found')] = {
                'Cve': vulnerability.get('Cve', ''),
                'CVSS': vulnerability.get('BaseScore', ''),
                'VRR': risk_rating,
                'ThreatCount': len(threat_list.get(vulnerability.get('Cve', ''), [])),
                'Trending': vulnerability.get('Trending', ''),
                'VulnLastTrendingOn': last_trending if last_trending else 'Not Found',
                'Threats': threat_list.get(vulnerability.get('Cve', ''), []),
                'Description': vulnerability.get('Description', '')
            }

    cve_list = []
    for cve in all_cves.values():
        if isinstance(cve, list):
            cve_list.extend(cve)
        else:
            cve_list.append(cve)

    return cve_list


def get_ransomware_cves():
    """
    Get a list of CVEs that contain ransomware threat

    :return: Demisto results entry
    """
    response = demisto.get(demisto.context(), 'RiskSense.HostFinding')

    if not response:
        return 'Key [RiskSense.HostFinding] was not found in context data.', {}, {}

    cve_list = get_cve_list_from_host_findings(response)

    ransomware_cves = []
    for cve in cve_list:
        for threat in cve.get('Threats', []):
            if threat.get('Category', '').lower() == 'ransomware':
                ransomware_cves.append(cve)
                break

    ec = {}
    readable_output = ''

    if len(ransomware_cves) > 0:
        readable_output += '### Total CVEs found: ' + str(len(ransomware_cves)) + '\n'
        readable_output += tableToMarkdown('List of CVEs that have ransomware threat', ransomware_cves,
                                           ['Cve', 'CVSS', 'VRR', 'ThreatCount', 'VulnLastTrendingOn', 'Trending'],
                                           header_transform, removeNull=True)
        ec['RiskSense.RansomwareCves(val.Cve && val.Cve == obj.Cve)'] = ransomware_cves
        return readable_output, ec, {}
    else:
        return 'No ransomware CVEs found.', ec, {}


def get_ransomware_trending_cves():
    """
    Get a list of CVEs which are currently ransomware trending

    :return: Demisto results entry
    """
    demisto.executeCommand('DeleteContext', {"key": "Date"})
    response = demisto.get(demisto.context(), 'RiskSense.HostFinding')

    today_date = date.today()
    week_ago_date = today_date - timedelta(days=7)
    ec = {'Date': {'CurrentDate': str(today_date), 'WeekAgoDate': str(week_ago_date)}}  # type: Dict[Any, Any]

    if not response:
        return 'Key [RiskSense.HostFinding] was not found in context data.', ec, {}

    cve_list = get_cve_list_from_host_findings(response)

    ransomware_cves = []  # type: List[Dict[str, Any]]
    for cve in cve_list:
        for threat in cve.get('Threats', []):
            if threat.get('Category', '').lower() == 'ransomware':
                ransomware_cves.append(cve)
                break

    ransomware_trending = []

    for cve in ransomware_cves:
        if cve.get('VulnLastTrendingOn') and cve.get('VulnLastTrendingOn') != 'Not Found':
            vuln_last_trending_on_date = datetime.strptime(cve.get('VulnLastTrendingOn', '2000-01-01'),
                                                           '%Y-%m-%d').date()
            if (today_date - vuln_last_trending_on_date).days <= 7:
                ransomware_trending.append(cve)

    readable_output = ''

    if len(ransomware_trending) > 0:
        readable_output += '### Total CVEs found: ' + str(len(ransomware_trending)) + '\n'
        readable_output += tableToMarkdown('List of CVEs that are ransomware trending', ransomware_trending,
                                           ['Cve', 'CVSS', 'VRR', 'ThreatCount', 'VulnLastTrendingOn', 'Trending'],
                                           header_transform, removeNull=True)
        ec['RiskSense.RansomwareTrendingCves(val.Cve && val.Cve == obj.Cve)'] = ransomware_trending
        return readable_output, ec, {}
    else:
        return 'No CVEs found With trending ransomware.', ec, {}


def display_cve_chart():
    """
    Display CVEs count data in chart format

    :return: Demisto results entry
    """

    response = demisto.get(demisto.context(), 'RiskSense')

    if not response:
        return_outputs('Key [RiskSense] was not found in context data.', {}, {})
        return

    ransomware_cves = response.get('RansomwareCves', [])
    trending_ransomware_cves = response.get('RansomwareTrendingCves', [])

    if isinstance(ransomware_cves, dict):
        ransomware_cves = [ransomware_cves]

    if isinstance(trending_ransomware_cves, dict):
        trending_ransomware_cves = [trending_ransomware_cves]

    entry_result = {
        "Type": 17,
        "ContentsFormat": "bar",
        "Contents": {
            "stats": [
                {
                    "data": [
                        len(ransomware_cves),
                    ],
                    "name": "CVEs that have ransomware threat",
                    "label": "CVEs that have ransomware threat",
                    "color": "rgb(0, 0, 255)"
                },
                {
                    "data": [
                        len(trending_ransomware_cves)
                    ],
                    "name": "CVEs that are ransomware trending",
                    "label": "CVEs that are ransomware trending",
                    "color": "rgb(255, 0, 0)"
                },
            ],
            "params": {
                "layout": "horizontal"
            }
        }
    }

    demisto.results(entry_result)


''' MAIN FUNCTION '''


def main():
    try:
        """
            PARSE AND VALIDATE INTEGRATION PARAMS
        """
        module = demisto.args().get('module_name')

        if module == 'Ransomware':
            return_outputs(*get_ransomware_cves())
        elif module == 'Trending Ransomware':
            return_outputs(*get_ransomware_trending_cves())
        elif module == 'Display CVEs Chart':
            display_cve_chart()
        else:
            return_error("Invalid module_name argument provided.")
    except Exception as exception:
        return_error(str(exception))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
