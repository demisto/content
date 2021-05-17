import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import base64


def encode(input):
    input_bytes = input.encode('utf-8')
    res = str(base64.b64encode(input_bytes))
    res = res.split('\'')[1]
    outputs = {
        'Base64': {
            'encoded': res
        }
    }
    return res, outputs


if __name__ in ('__main__', 'builtins', '__builtin__'):
    try:
        input = demisto.args().get('input')
        return_outputs(*encode(input))
    except Exception as e:
        return_error('Error occurred while running the command. Exception info:\n' + str(e))
