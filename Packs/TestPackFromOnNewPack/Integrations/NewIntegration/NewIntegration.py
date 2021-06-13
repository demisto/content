import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    demisto.results('ok')
    sys.exit(0)
if demisto.command() == 'fetch-incidents':
    # You can store the last run time...
    demisto.setLastRun({'time': 'now'})
    # And retrieve it for use later:
    lastRun = demisto.getLastRun()
    # lastRun is a dictionary, with value "now" for key "time".
    # JSON of the incident type created by this integration
    demisto.incidents([{"Name": "Incident #1"}, {"Name": "Incident #2"}])
    sys.exit(0)
# You can use demisto.args()[argName] to get a specific arg. args are strings.
# You can use demisto.params()[paramName] to get a specific params.
# Params are of the type given in the integration page creation.

if demisto.command() == 'long-running-execution':
    # Should have here an endless loop
    print("yana new")
