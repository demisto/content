import re
import string

# Optional arguments and default values
chars = 4
if 'chars' in demisto.args():
    chars = int(demisto.args()['chars'])

size = 1024
if 'size' in demisto.args():
    size = int(demisto.args()['size'])

regex = None
if 'filter' in demisto.args():
    regex = re.compile(demisto.args()['filter'], re.I)

fEntry = demisto.executeCommand('getFilePath', {'id': demisto.args()['entry']})[0]
if not isError(fEntry):
    matches = []
    with open(demisto.get(fEntry, 'Contents.path'), 'rb', 1024 * 1024) as f:
        buff = ''
        c = f.read(1)
        while c != '':
            if c in string.printable:
                buff += c
                if len(buff) >= 32 * 1024:
                    matches.append('File is a regular text file')
                    break
            else:
                if len(buff) >= chars:
                    if regex:
                        if regex.match(buff):
                            matches.append(buff)
                    else:
                        matches.append(buff)
                    if len(matches) >= size:
                        break
                buff = ''
            c = f.read(1)
    if matches:
        demisto.results('\n'.join(matches))
    else:
        demisto.results('No strings were found.')
else:
    demisto.results(fEntry)
