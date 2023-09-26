import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import re


def get_plain_text(html: str, replace_line_breaks: bool, trim_result: bool):
    data = ''
    if html:
        data = re.sub(r'<\/?br\s?\/?>', '\n', html, flags=re.I) if replace_line_breaks else html

        data = re.sub(r'<.*?>', '', html, flags=re.I)
        entities = {'quot': '"', 'amp': '&', 'apos': "'", 'lt': '<', 'gt': '>', 'nbsp': ' ',
                    'copy': '(C)', 'reg': '(R)', 'tilde': '~', 'ldquo': '"', 'rdquo': '"', 'hellip': '...'}
        for e in entities:
            data = data.replace(f'&{e};', entities[e])

        if trim_result:
            data = re.sub(r'[ \t]{2,}', ' ', data)
            data = re.sub(r'(\s*\r?\n){3,}', '\n\n', data)
            data = data.strip()
    return data


def get_body(html: str, html_tag: str, allow_fallback: bool = False):
    if html and html_tag:
        body = re.search(fr'<{html_tag}.*/{html_tag}>', html, re.M + re.S + re.I + re.U)

        if body and body.group(0):
            return body.group(0)
        elif allow_fallback and html_tag.lower() == 'body':
            return html
    return ''


def text_from_html(args: dict):
    html = args['html']
    html_tag = args.get('html_tag', 'body')
    allow_fallback = str(args.get('allow_body_fallback', 'false')).lower() == 'true'
    replace_line_breaks = str(args.get('replace_line_breaks', 'false')).lower() == 'true'
    trim_result = str(args.get('trim_result', 'false')).lower() == 'true'

    body = get_body(html, html_tag, allow_fallback)
    data = get_plain_text(body, replace_line_breaks, trim_result)

    return data if data != '' else 'Could not extract text'


def main():
    try:
        text = text_from_html(demisto.args())
        context_path = demisto.args().get('context_path', None)
        result = CommandResults(
            outputs_prefix=context_path,
            outputs=text if context_path else None,
            readable_output=text
        )

        return_results(result)
    except Exception as ex:
        return_error(message="failed to extract text", error=ex)


if __name__ in ["__builtin__", "builtins"]:
    main()
