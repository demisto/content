import demistomock as demisto
from CommonServerPython import *

import base64


def decode(value):
    decoded_bytes = base64.urlsafe_b64decode(str(value))
    res = decoded_bytes.decode(errors='ignore')

    outputs = {
        "Base64":
            {
                "originalValue": value,
                "decoded": res
            }
    }

    return res, outputs


if __name__ in ('builtins', '__builtin__'):
    value = demisto.args()["value"]
    return_outputs(*decode(value))
