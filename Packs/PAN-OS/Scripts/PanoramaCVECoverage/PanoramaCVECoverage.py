import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


OUTPUT_HEADERS = ['Threat Name', 'Link', 'Severity', 'Threat ID', 'Default Action']


def main():
    try:
        # Input arguments
        args = demisto.args()
        cve_list = argToList(args.get('CVE_List'))
        pan_os_output = args.get('Result_file')
        output_format = args.get('outputFormat', 'table')

        # read the file content
        read_file_output = demisto.executeCommand("ReadFile", {"entryID": pan_os_output, "maxFileSize": "100000000"})
        if isError(read_file_output):
            return_error(f'Failed to execute ReadFile command: {get_error(read_file_output)}')

        pan_os_output = read_file_output[0].get('EntryContext').get('FileData')

        # CVE data from the firewall
        data = json.loads(pan_os_output)

        findings: Dict[str, List] = {}

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
                    output_fields = {'threat_name': threat_name, 'link': link, 'severity': severity,
                                     'threat_id': threat_id, 'default_action': action}
                    if cve in findings:
                        findings[cve].append(output_fields)
                    else:
                        findings[cve] = [output_fields]

        # Start of markdown output formatting
        res = '## CVE Coverage\n'
        for queriedCVE in cve_list:
            if queriedCVE in findings:
                if output_format == 'table':
                    section = tableToMarkdown(queriedCVE, findings[queriedCVE], headerTransform=string_to_table_header)
                else:
                    section = '### %s\n' % queriedCVE
                    rows = [','.join([entry[fieldName] for fieldName in entry.keys()]) for entry in findings[queriedCVE]]
                    section += '\n'.join(rows)
                res += section
            else:
                res += '### %s\nNo coverage for %s' % (queriedCVE, queriedCVE)
            res += '\n'
        res += '\n\n'

        # create the context outputs
        outputs = []
        for queried_CVE in findings.keys():
            outputs.append({'CVE': queried_CVE,
                            'Coverage': findings[queried_CVE]})
    except Exception as e:
        return_error(str(e))

    return_results(CommandResults(readable_output=res,
                                  outputs_key_field='CVE',
                                  outputs=outputs,
                                  outputs_prefix='Panorama.CVECoverage'))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
