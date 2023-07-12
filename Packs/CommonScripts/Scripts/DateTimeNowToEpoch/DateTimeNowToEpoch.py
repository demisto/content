import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Return current epoch value for datetime.now
demisto.results(int(time.time()))
