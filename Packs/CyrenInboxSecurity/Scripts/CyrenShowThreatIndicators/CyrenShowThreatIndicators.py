import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# noqa: F401
# noqa: F401
# type: ignore

import json


def stringify_indicators(threat_indicators):
    markdown_result = ""
    indicator_type = threat_indicators.get('type')
    indicator_value = threat_indicators.get('value')
    # url indicators
    if indicator_type == 'url':
        if threat_indicators.get('attachment') is not None:
            indicator_type = 'URL in attachment'
        else:
            indicator_type = 'URL in body'
        markdown_result += '|Type|Value|\n|---|---|\n'
        markdown_result +=\
            '|' +\
            indicator_type +\
            '|' +\
            indicator_value +\
            '|\n\n'

        return markdown_result

    # attachment indicators
    if indicator_type == 'attachment':
        attachment = threat_indicators.get('attachment')
        markdown_result +=\
            '|Type|Filename|Size|Category|Hash|' \
            '\n|---|---|---|---|---|\n'
        markdown_result += (
            '|'
            + 'Attachment'
            + '|'
            + str(attachment.get('file_name', ''))
            + '|'
            + str(attachment.get('file_size', ''))
            + '|'
            + str(attachment.get('file_category', ''))
            + '|'
            + str(attachment.get('file_hash', ''))
            + '|\n\n'
        )
        return markdown_result

    # other indicators
    if threat_indicators.get("type") is not None:
        markdown_result += '|Type|Value|\n|---|---|\n'
        markdown_result +=\
            '|' +\
            indicator_type +\
            '|' +\
            indicator_value +\
            '|\n\n'

    return markdown_result


def no_indicators():
    return {
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': "No indicators identified by system."
                    " _Refer to user feedback._\n"
    }


def main():

    try:
        threat_indicators = demisto.get(
            demisto.incidents()[0],
            'CustomFields.cyrenthreatindicators'
        )
        if not threat_indicators:
            threat_indicators = "[]"

        threat_indicators = json.loads(threat_indicators)
        markdown_result = ""

        # show threat indicators
        if isinstance(threat_indicators, list):
            markdown_result +=\
                "**Number of" \
                " indicators:**&nbsp;&nbsp;&nbsp;&nbsp; {}\n\n".\
                format(len(threat_indicators))
            for x in threat_indicators:
                markdown_result += stringify_indicators(x)
        else:
            markdown_result += stringify_indicators(threat_indicators)

        if markdown_result == "":
            return no_indicators()

        return {'ContentsFormat': formats['markdown'],
                'Type': entryTypes['note'],
                'Contents': markdown_result}

    except Exception as e:
        return_error(f'Failed to execute'
                     f' CyrenShowThreatIndicators. Error: {str(e)}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    entry = main()
    return_results(entry)
