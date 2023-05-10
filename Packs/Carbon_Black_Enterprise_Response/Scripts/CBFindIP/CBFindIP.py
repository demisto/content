import demistomock as demisto
from CommonServerPython import *

''' MAIN FUNCTION '''


def main():
    t = []  # type: list
    found = []
    ips = argToList(demisto.args()['ip'])
    for ip in ips:
        for e in demisto.executeCommand('cb-get-processes', {'query': 'ipaddr:' + ip}):
            if isError(e):
                return_error(e['Contents'])
            else:
                found.append(ip)
                t += e['HumanReadable']
    if t:
        appendContext("found_ips", ','.join(found), dedup=True)
        demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': e['HumanReadable'],
                         'EntryContext': e['EntryContext']})


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
