import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import base64


def encode(input):
    input_bytes = input.encode('utf-8')
    res = base64.b64encode(input_bytes)
    outputs = {
        'Base64': {
            'encoded': res
        }
    }

    return res, outputs


if __name__ in ('builtins', '__builtin__'):
    input = demisto.args().get('input')
    return_outputs(*encode(input))