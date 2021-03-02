import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# type: ignore

import collections
from dateutil import parser
import json


def stringify_attachment(attachment):
    markdown_result = ""
    markdown_result += '|Name|Size|Category|Hash|\n|---|---|---|---|\n'
    markdown_result += '|**' + attachment["file_name"] + '**|' + \
        f'{attachment["file_size"]:,}' + '|' + attachment["file_category"] + '|' + attachment["file_hash"] + '|\n\n'

    return markdown_result


def no_attachments():
    return {
        'ContentsFormat': formats['markdown'],
        'Type': entryTypes['note'],
        'Contents': "No attachments\n"
    }


def main():

    # threat indicators
    # raise NameError(demisto.incidents()[0])
    message_details = demisto.get(demisto.incidents()[0], 'CustomFields.cyrenmessagedetails')
    if not message_details:
        return no_attachments()

    message_details = json.loads(message_details)
    markdown_result = ""

    attachments = message_details["attachments"]
    if len(attachments) == 0:
        return no_attachments()

    # raise NameError(attachments)
    for x in attachments:
        markdown_result += stringify_attachment(x)

    return {'ContentsFormat': formats['markdown'],
            'Type': entryTypes['note'],
            'Contents': markdown_result}


if __name__ in ['__main__', '__builtin__', 'builtins']:
    entry = main()
    demisto.results(entry)
