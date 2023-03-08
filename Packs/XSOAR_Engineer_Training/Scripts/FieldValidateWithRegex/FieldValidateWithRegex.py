import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Field Change trigger script can take an "old" and "new" and then act accordingly.
# Can be used on fields like severity, or owner to do different actions such as escalation or notification.

import re

new = demisto.args().get("new")
field = demisto.args().get("cliName")

if not re.match("\d{5}", new) and new != "":
    return_error(f"{new} is not a valid employee number, must be 5 digits {field}")
