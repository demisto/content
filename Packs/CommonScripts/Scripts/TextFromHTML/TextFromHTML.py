import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import re


def get_plain_text(html: str, replace_line_breaks: bool, trim_result: bool):
    data = ''
    if html:
        data = re.sub(r'<\/?br\s?\/?>', '\n', html, flags=re.I) if replace_line_breaks else html

        data = re.sub(r'<.*?>', '', data)
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


def main():  # pragma: no cover
    try:
        args = demisto.args()
        html = args['html']
        html_tag = args.get('html_tag', 'body')
        allow_fallback = argToBoolean(args.get('allow_body_fallback', 'false'))
        replace_line_breaks = argToBoolean(args.get('replace_line_breaks', 'false'))
        trim_result = argToBoolean(args.get('trim_result', 'false'))
        context_path = argToBoolean(demisto.args().get('output_to_context', 'false'))

        body = get_body(html, html_tag, allow_fallback)
        text = get_plain_text(body, replace_line_breaks, trim_result)
        text = text if text != '' else 'Could not extract text'

        result = CommandResults(
            outputs_prefix='TextFromHTML',
            outputs=text if context_path else None,
            raw_response=text,
            readable_output=text,
        )

        return_results(result)
    except Exception as ex:
        return_error(message="Failed to extract text", error=ex)


if __name__ in ["__builtin__", "builtins"]:
    main()
