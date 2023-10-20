import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytz

''' get the timezone information '''
tz = demisto.args().get('timezone')

now = datetime.now(pytz.timezone(tz)) if tz is not None else datetime.now()

ec = {"currentDatetime": now.strftime("%Y-%m-%dT%H:%M:%S")}

demisto.results({
    'ContentsFormat': formats["text"],
    'Type': entryTypes["note"],
    'Contents': now.strftime("%Y-%m-%dT%H:%M:%S"),
    'HumanReadable': now.strftime("%Y-%m-%dT%H:%M:%S"),
    'EntryContext': ec
})
