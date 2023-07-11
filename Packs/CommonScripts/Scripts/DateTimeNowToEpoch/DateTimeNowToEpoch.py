import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime
import calendar

demisto.results(calendar.timegm(datetime.now().timetuple()))
