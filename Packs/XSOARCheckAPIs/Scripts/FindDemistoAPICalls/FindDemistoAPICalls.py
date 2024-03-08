import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re


def FindURI(data, var_name):
    pattern = f"{var_name}(?:\s+)(?:[=\s]+)?(?:[f\\\'\\\"]+)?([^\\\'\\\"]+)(?:[\\\"\\\']+).*"
    for line in data:
        # result = line.split()
        if var_name in line:
            match = re.search(pattern, line)
            if match:
                return match.group(1)


def main(args):
    demisto_api_pattern = r".*?(demisto-api[^\s\\\'\\\"]+)(?:.*)(?:uri[\\\'\\\"]+:)(?:[\s\\\'\\\"]+)(?:[f\\\'\\\"]+)?([^\\\'\\\"\}\,\{]+).*"
    core_api_pattern = r".*?(core-api[^\s\\\'\\\"]+)(?:.*)(?:uri[\\\'\\\"]+:)(?:[\s\\\'\\\"]+)(?:[f\\\'\\\"]+)?([^\\\'\\\"\}\,\{]+).*"
    File = args.get('File', '')
    EntryID = args.get('EntryID', '')

    if not File and not EntryID:
        demisto.error("Either File or EntryID must be provided")
    elif EntryID:
        res = demisto.executeCommand('getFilePath', {'id': EntryID})
        entry = demisto.executeCommand("getEntry", {"id": EntryID})
        filename = entry[0].get('File')
    else:
        res = demisto.executeCommand('getFilePath', {'id': File.get('EntryID')})
    if res[0]['Type'] == entryTypes['error']:
        demisto.results('File not found')

    Results: list = []
    try:
        with open(res[0]['Contents']['path'], 'r') as file:
            data = file.readlines()

            for line in data:
                result = {}
                match = None
                # Match legacy demisto-api calls:
                if ('demisto-api' in line):
                    match = re.search(demisto_api_pattern, line)

                # Match new core-api calls:
                elif ('core-api' in line):
                    match = re.search(core_api_pattern, line)

                if match:
                    demisto.debug("Match Found")
                    command = match.group(1)
                    uri = match.group(2)
                    if "/" not in uri:
                        uri = FindURI(data, uri.strip())
                    filename = File['Name'] if File else filename
                    result['automation_name'] = filename.replace('automation-', '').replace('.yml', '')
                    result['api_call'] = command
                    result['api_endpoint'] = uri
                    Results.append(result)

        entry = {'Type': entryTypes['note'],
                 'Contents': Results,
                 'ContentsFormat': formats['json'],
                 'HumanReadable': tableToMarkdown("Results", Results, headers=[]),
                 'ReadableContentsFormat': formats['markdown'],
                 'EntryContext': {"Results": Results},
                 }

        demisto.results(entry)

    except ValueError:  # includes simplejson.decoder.JSONDecodeError
        demisto.results('Decoding JSON has failed')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.args())
