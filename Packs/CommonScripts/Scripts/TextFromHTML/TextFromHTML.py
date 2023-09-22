import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import re


def get_plain_text(html):
    data = ''
    if html:
        data = re.sub(r'<.*?>', '', html, flags=re.M + re.S + re.I + re.U)
        entities = {'quot': '"', 'amp': '&', 'apos': "'", 'lt': '<', 'gt': '>', 'nbsp': ' ',
                    'copy': '(C)', 'reg': '(R)', 'tilde': '~', 'ldquo': '"', 'rdquo': '"', 'hellip': '...'}
        for e in entities:
            data = data.replace(f'&{e};', entities[e])
        data = re.sub(r'[ \t]{2,}', ' ', data)
        data = re.sub(r'(\r?\n){2,}', '\n', data)
    return data


def get_body(html, html_tag, allow_fallback=False):
    if html and html_tag:
        body = re.search(fr'<{html_tag}.*/{html_tag}>', html, re.M + re.S + re.I + re.U)

        if body and body.group(0):
            return body.group(0)
        elif allow_fallback and html_tag.lower() == 'body':
            return html
    return ''


def text_from_html(args):
    html = args['html']
    html_tag = args.get('html_tag', 'body')
    allow_fallback = str(args.get('allow_body_fallback', 'false')).lower() == 'true'

    body = get_body(html, html_tag, allow_fallback)
    data = get_plain_text(body)

    return data if data != '' else 'Could not extract text'


if __name__ in ["__builtin__", "builtins"]:
    result = text_from_html(demisto.args())
    demisto.results(result)
