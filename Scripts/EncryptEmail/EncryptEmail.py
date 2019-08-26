import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import smime


def main():
    message_body = demisto.args().get('message')
    encrypt_key = demisto.getFilePath(demisto.args().get('key'))

    with open(encrypt_key['path'], 'rb') as pem:
        msg = smime.encrypt(message_body, pem.read())

    entry_context = {
        'Email': {
            'Message': msg
        }
    }
    return_outputs(msg, entry_context)


if __name__ in ('__builtin__', 'builtins'):
    main()
