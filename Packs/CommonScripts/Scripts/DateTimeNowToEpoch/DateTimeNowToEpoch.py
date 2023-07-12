import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime
import calendar

# Return current epoch value for datetime.now
demisto.results(calendar.timegm(datetime.now().timetuple()))
