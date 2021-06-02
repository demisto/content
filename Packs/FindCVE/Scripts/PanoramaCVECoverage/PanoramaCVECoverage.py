
import demistomock as demisto
from CommonServerPython import *

my_fields = ['CVE', 'Threat Name', 'Link', 'Severity', 'Threat ID', 'Default Action']


def main():
    # Input arguments

    # The CVE we are looking for
    cve_arg = demisto.args().get('CVE_List')
    queriedCVEs = cve_arg.split()

    # CVE data from the firewall
    PanOSOutput = demisto.args().get('Result_file')
    data = json.loads(PanOSOutput)

    findings: Dict[List, List] = {}
    # Correlating the corresponding CVE list to reference link, severity, threat_id, and default action.
    for entry in data['threats']['vulnerability']['entry']:
        if 'cve' in entry:
            cve = entry['cve']['member']
            if cve in queriedCVEs:
                link = "http://cve.circl.lu/api/cve/" + cve
                threatName = entry['threatname']
                severity = entry['severity']
                threatID = entry['@name']
                action = entry.get('default-action', 'No Action Defined')
                outputFields = {'CVE': cve, 'Threat Name': threatName, 'Link': link, 'Severity': severity,
                                'Threat ID': threatID, 'Default Action': action}
                if cve in findings:
                    findings[cve].append(outputFields)
                else:
                    findings[cve] = [outputFields]

    view = demisto.args().get('outputFormat', '')

    # Start of markdown output formatting
    res = '## CVE Coverage\n'
    for queriedCVE in queriedCVEs:
        if queriedCVE in findings:
            if view == 'table':
                section = tableToMarkdown(queriedCVE, findings[queriedCVE], my_fields)
            else:
                section = '### %s\n' % queriedCVE
                rows = [','.join([entry[fieldName] for fieldName in my_fields]) for entry in findings[queriedCVE]]
                section += '\n'.join(rows)
            res += section
        else:
            res += '### %s\nNo coverage for %s' % (queriedCVE, queriedCVE)
        res += '\n'
    res += '\n\n'
    demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': res})


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
