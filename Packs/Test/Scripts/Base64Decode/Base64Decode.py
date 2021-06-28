import base64

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def decode(value):
    decoded_bytes = base64.urlsafe_b64decode(str(value))
    res = str(decoded_bytes)

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
