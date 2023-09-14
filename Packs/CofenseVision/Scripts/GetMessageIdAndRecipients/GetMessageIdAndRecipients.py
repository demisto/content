import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, List


def main():
    try:
        args: Dict = demisto.args()
        root = args.get('key')
        if root:
            if not isinstance(root, list):
                root = [root]

            t: List = []
            for obj in root:
                internet_message_id = obj.get('internetMessageId')
                recipients = obj.get('recipients', [])
                if internet_message_id and recipients:
                    messages = []
                    for recipient in recipients:
                        address = recipient.get('address')
                        if address:
                            messages.append(f'{internet_message_id}:{address}')
                    t.extend(messages)

            demisto.results(t)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not format data.\n{e}')


if __name__ in ('builtins', '__builtin__'):
    main()
