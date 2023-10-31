import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    demisto.results('ok')
    sys.exit(0)
