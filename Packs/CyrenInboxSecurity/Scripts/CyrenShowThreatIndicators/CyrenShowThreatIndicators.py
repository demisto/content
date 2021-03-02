import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# type: ignore

import collections
from dateutil import parser
import json


def stringify_indicators(threat_indicators):
    markdown_result = ""
    if threat_indicators.get("type") is not None:
        markdown_result += '|Type|Value|\n|---|---|\n'
        markdown_result += '|' + threat_indicators["type"] + '|' + threat_indicators["value"] + '|\n\n'

        attachment = threat_indicators["attachment"]
        file_hash = attachment["file_hash"]
        if file_hash is not None:
            markdown_result += '|Filename|size|category|\n|---|---|---|\n'
            markdown_result += '|' + attachment["file_name"] + '|' + \
                str(attachment["file_size"]) + '|' + str(attachment["file_category"]) + '|\n\n'

    return markdown_result


def no_indicators():
    return {
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': "No indicators identified by system. _Refer to user feedback._\n"
    }


def main():

    threat_type = demisto.get(demisto.incidents()[0], 'CustomFields.cyrenthreattype')
    threat_indicators = demisto.get(demisto.incidents()[0], 'CustomFields.cyrenthreatindicators')
    if not threat_indicators:
        threat_indicators = "[]"
    message_details = demisto.get(demisto.incidents()[0], 'CustomFields.cyrenmessagedetails')
    if not message_details:
        message_details = "{}"

    message_details = json.loads(message_details)
    threat_indicators = json.loads(threat_indicators)
    markdown_result = ""

    # show external from/recipient details
    if message_details.get("is_external_from"):
        markdown_result += "**External Sender:**&nbsp;&nbsp;&nbsp;&nbsp; Yes\n\n"
    if message_details.get("is_external_reply_to"):
        markdown_result += "**External Reply To:**&nbsp; Yes\n\n"

    # show threat indicators
    if isinstance(threat_indicators, list):
        for x in threat_indicators:
            markdown_result += stringify_indicators(x)
    else:
        markdown_result += stringify_indicators(threat_indicators)

    if markdown_result == "":
        return no_indicators()

    return {'ContentsFormat': formats['markdown'],
            'Type': entryTypes['note'],
            'Contents': markdown_result}


if __name__ in ['__main__', '__builtin__', 'builtins']:
    entry = main()
    demisto.results(entry)
