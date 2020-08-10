import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import base64


def encode(input):
    input_bytes = input.endcode('utf-8')
    res = base64.b64encode(input_bytes)


