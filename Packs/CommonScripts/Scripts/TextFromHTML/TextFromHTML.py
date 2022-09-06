import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re


def text_from_html(args):
    html = args['html']
    body = re.search(r'<body.*/body>', html, re.M + re.S + re.I + re.U)
    if body and body.group(0):
        data = re.sub(r'<.*?>', '', body.group(0))
        entities = {'quot': '"', 'amp': '&', 'apos': "'", 'lt': '<', 'gt': '>', 'nbsp': ' ',
                    'copy': '(C)', 'reg': '(R)', 'tilde': '~', 'ldquo': '"', 'rdquo': '"', 'hellip': '...'}
        for e in entities:
            data = data.replace('&' + e + ';', entities[e])

        return data
    else:
        return 'Could not extract text'


if __name__ in ["__builtin__", "builtins"]:
    result = text_from_html(demisto.args())
    demisto.results(result)
