import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import re


def get_plain_text(html_regex):
    data = ''
    if html_regex and html_regex.group(0):
        data = re.sub(r'<.*?>', '', html_regex.group(0))
        entities = {'quot': '"', 'amp': '&', 'apos': "'", 'lt': '<', 'gt': '>', 'nbsp': ' ',
                    'copy': '(C)', 'reg': '(R)', 'tilde': '~', 'ldquo': '"', 'rdquo': '"', 'hellip': '...'}
        for e in entities:
            data = data.replace(f'&{e};', entities[e])
    return data


def text_from_html(args):
    html = args['html']
    html_tag = args.get('html_tag', 'body')

    body = re.search(fr'<{html_tag}.*/{html_tag}>', html, re.M + re.S + re.I + re.U)
    data = get_plain_text(body)
    return data if data != '' else 'Could not extract text'


if __name__ in ["__builtin__", "builtins"]:
    result = text_from_html(demisto.args())
    demisto.results(result)
