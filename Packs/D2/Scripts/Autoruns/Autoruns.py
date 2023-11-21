import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

respAR = demisto.executeCommand('D2Autoruns', {'using': demisto.args()['system']})
if isError(respAR[0]):
    demisto.results(respAR)
else:
    hashes = []
    try:
        try:
            lines = respAR[0]['Contents'][2:].decode('utf-16').encode('ascii').split('\r\n')
        except Exception:
            lines = respAR[0]['Contents'].split('\r\n')
        headers = lines[5].replace('\t', '|')
        try:
            hashCol = headers.split('|').index('MD5')
        except ValueError:
            hashCol = -1
        mdTable = headers + '\n'
        mdTable += '|'.join('---' * len(headers.split('|'))) + '\n'
        for line in lines[6:]:
            if hashCol > -1:
                cells = line.split('\t')
                if hashCol < len(cells) and cells[hashCol].strip():
                    hashes.append(cells[hashCol])
            mdTable += line.replace('\t', '|') + '\n'
        if hashes:
            appendContext('md5s', ', '.join(hashes), dedup=True)
        demisto.results({'Type': entryTypes['note'], 'ContentsFormat': formats['markdown'], 'Contents': mdTable})
    except Exception as ex:
        contents = "Error occurred while parsing output from D2Autoruns:\n"
        contents += str(ex) + '\n\nAutoruns output:\n' + respAR[0]['Contents']
        demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                        'Contents': contents})
