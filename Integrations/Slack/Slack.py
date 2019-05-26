import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    demisto.results('ok')
    sys.exit(0)

if demisto.command() == 'long-running-execution':
  # Should have here an endless loop
`
