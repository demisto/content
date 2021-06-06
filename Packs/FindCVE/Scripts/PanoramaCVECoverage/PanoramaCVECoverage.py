
import demistomock as demisto
from CommonServerPython import *

OUTPUT_HEADERS = ['CVE', 'Threat Name', 'Link', 'Severity', 'Threat ID', 'Default Action']


def main():
    # Input arguments
    args = demisto.args()
    # The CVE we are looking for
    cve_list = argToList(args.get('CVE_List'))
    # CVE data from the firewall
    pan_os_output = args.get('entryID')

    output_format = args.get('outputFormat', '')

    read_file_output = demisto.executeCommand("ReadFile", {"entryID": pan_os_output, "maxFileSize": "100000000"})
    if isError(read_file_output):
        return_error(f'Failed to execute ReadFile command: {get_error(read_file_output)}')
    pan_os_output = read_file_output[0].get('EntryContext').get('FileData')

    data = json.loads(pan_os_output)

    findings = {}

    # Correlating the corresponding CVE list to reference link, severity, threat_id, and default action.
    for entry in data['threats']['vulnerability']['entry']:
        if 'cve' in entry:
            cve = entry['cve']['member']
            if cve in cve_list:
                link = "http://cve.circl.lu/api/cve/" + cve
                threat_name = entry.get('threatname')
                severity = entry.get('severity')
                threat_id = entry.get('@name')
                action = entry.get('default-action', 'No Action Defined')
                output_fields = {'CVE': cve, 'Threat Name': threat_name, 'Link': link, 'Severity': severity,
                                'Threat ID': threat_id, 'Default Action': action}
                if cve in findings:
                    findings[cve].append(output_fields)
                else:
                    findings[cve] = [output_fields]

    # Start of markdown output formatting
    res = '## CVE Coverage\n'
    for queriedCVE in cve_list:
        if queriedCVE in findings:
            if output_format == 'table':
                section = tableToMarkdown(queriedCVE, findings[queriedCVE], OUTPUT_HEADERS)
            else:
                section = '### %s\n' % queriedCVE
                rows = [','.join([entry[fieldName] for fieldName in OUTPUT_HEADERS]) for entry in findings[queriedCVE]]
                section += '\n'.join(rows)
            res += section
        else:
            res += '### %s\nNo coverage for %s' % (queriedCVE, queriedCVE)
        res += '\n'
    res += '\n\n'

    return_results(CommandResults(readable_output=res))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
