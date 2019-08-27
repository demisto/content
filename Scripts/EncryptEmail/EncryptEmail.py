import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import smime


def main():
    message_body = demisto.args().get('message')
    encrypt_key = demisto.getFilePath(demisto.args().get('key'))

    with open(encrypt_key['path'], 'rb') as pem:
        msg = smime.encrypt(message_body, pem.read())
    new_message = msg.split('\n\n')
    headers = new_message[0]
    content = new_message[1]

    entry_context = {
        'Email': {
            'Message': content,
            'Headers': headers
        }
    }
    return_outputs(content, entry_context)


if __name__ in ('__builtin__', 'builtins'):
    main()
