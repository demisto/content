import datetime

import demistomock as demisto  # noqa: F401
import pytz
from CommonServerPython import *  # noqa: F401

date = demisto.getArg('date')
date_format = demisto.getArg('date_format')
timezone = demisto.getArg('timezone')

timezone = pytz.timezone(timezone)

# Initialize datetime
date = datetime.datetime.strptime(date, date_format)

# Convert to timezone aware date
localized_date = timezone.localize(date)

# Convert to UTC timezone
utc_converted_date = localized_date.astimezone(pytz.timezone("UTC"))
epoch_time = utc_converted_date.strftime('%s')

# Initialize entry context to return
entry_context = {}
entry_context['UTCDate'] = utc_converted_date.strftime(date_format)
entry_context['UTCDateEpoch'] = epoch_time

demisto.results({
    'Contents': json.dumps(entry_context),
    'ContentsFormat': formats['json'],
    'EntryContext': entry_context
}
)
