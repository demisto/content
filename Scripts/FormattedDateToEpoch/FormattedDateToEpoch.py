import demistomock as demisto
from datetime import datetime

date_value = demisto.args()['value']
formatter = demisto.args()['formatter']

date_obj = datetime.strptime(date_value, formatter)

demisto.results(int(date_obj.strftime('%s')))
