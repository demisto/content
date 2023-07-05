import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from email.header import decode_header


def decode(s):
    dh = decode_header(s.strip())
    default_charset = 'ASCII'
    res = ''.join([str(t[0], t[1] or default_charset) for t in dh])
    return res


def main():     # pragma: no cover
    s = demisto.args()['value']

    if s.startswith('"'):
        s = s[1:]

    if s.endswith('"'):
        s = s[:-1]

    lines = []
    for line in s.split("\n"):
        try:
            lines.append(decode(line))
        except Exception:
            lines.append(line)

    res = "\n".join(lines)
    demisto.results({'ContentsFormat': formats['text'],
                     'Type': entryTypes['note'],
                     'Contents': res,
                     'EntryContext': {'DecodedMimeHeader': res}
                     })


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
