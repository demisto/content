import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json


def stringify_indicators(threat_indicators):
    #

    indicator_type = threat_indicators.get('type')

    # url indicators
    if indicator_type == 'url':
        return tableToMarkdown("", threat_indicators, ["type", "subType", "value"], pretty_title) + '\n\n'

    # attachment indicators
    if indicator_type == 'attachment':
        attachment = threat_indicators.get('attachment', [])
        attachment["type"] = "attachment"
        return tableToMarkdown("", attachment,
                               ["type", "file_name", "file_size", "file_category", "file_hash"],
                               pretty_title) + '\n\n'

    # other indicators
    if threat_indicators.get("type") is not None:
        return tableToMarkdown("", threat_indicators, ["type", "value"], pretty_title) + '\n\n'
    return None


def pretty_title(s):
    s = s.replace('_', ' ')
    return pascalToSpace(s)


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
