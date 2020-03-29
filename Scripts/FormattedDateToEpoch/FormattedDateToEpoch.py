import demistomock as demisto
from CommonServerPython import *

from datetime import datetime

date_value = demisto.args()['value']
formatter = demisto.args()['formatter']

date_obj = datetime.strptime(date_value, formatter)

return_outputs(date_obj.strftime('%s'), {'EpochTime': int(date_obj.strftime('%s'))}, '')
