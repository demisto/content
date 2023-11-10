import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
last_hour_date_time = datetime.now() - timedelta(hours = 2)
print(last_hour_date_time)
print(last_hour_date_time.strftime('%Y-%m-%d %H:%M:%S'))
now=datetime.now()
date={'date':str(last_hour_date_time)}
date_now={'date_now':str(now)}
date.update(date_now)
results=CommandResults(outputs=date,outputs_prefix='date')
return_results(results)
