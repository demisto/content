import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# return the args to the war room, useful for seeing what you have available to you
# args can be called with demisto.args().get('argname')
demisto.results(demisto.args())
