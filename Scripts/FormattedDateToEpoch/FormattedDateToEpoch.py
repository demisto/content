import demistomock as demisto
from datetime import datetime, timezone

epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)

args = demisto.args()
date_value = args['value']
formatter = args['formatter']

date_obj = datetime.strptime(date_value, formatter)
unix_time = int(date_obj.strftime('%s') if date_obj.tzinfo is None else (date_obj - epoch).total_seconds())

demisto.results(unix_time)
