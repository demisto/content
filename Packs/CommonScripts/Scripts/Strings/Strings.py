import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import string


def strings(args):
    # Optional arguments and default values
    chars = 4
    if 'chars' in args:
        chars = int(args['chars'])
    size = 1024
    if 'size' in args:
        size = int(args['size'])
    regex = None
    if 'filter' in args:
        regex = re.compile(args['filter'], re.I)
    fEntry = demisto.executeCommand('getFilePath', {'id': args['entry']})[0]
    if not isError(fEntry):
        matches = []
        with open(demisto.get(fEntry, 'Contents.path'), 1024 * 1024, errors='ignore') as f:
            buff = ''
            c = f.read(1)
            while c != '':
                if c in string.printable:
                    buff += c
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
            if len(buff) >= chars and len(matches) < size:
                if regex:
                    if regex.match(buff):
                        matches.append(buff)
                else:
                    matches.append(buff)
        if matches:
            return '\n'.join(matches)
        else:
            return 'No strings were found.'
    else:
        return fEntry


def main():
    args = demisto.args()
    demisto.results(strings(args))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
