import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from subprocess import Popen, PIPE


def main():
    domain = demisto.args().get('domain')

    cmd = ['aquatone-discover', '--domain', domain]

    p = Popen(cmd, stdout=PIPE, stderr=PIPE, encoding="utf-8")

    stdout, stderr = p.communicate()

    if p.returncode > 0:
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": stdout + stderr})
    else:
        res = stdout
        cmd = ['cat', '/root/aquatone/' + domain + '/hosts.json']
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, encoding="utf-8")
        stdout, stderr = p.communicate()
        if p.returncode > 0:
            demisto.results(
                {"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": stdout + stderr})
        else:
            hosts = stdout
            hosts_json = json.loads(hosts)

            ec = {'Aquatone.discover': hosts_json}
            entry_result = {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': hosts_json,
                'HumanReadable': res,
                'ReadableContentsFormat': formats['markdown'],
                'EntryContext': ec
            }
            demisto.results(entry_result)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
