import demistomock as demisto
from CommonServerPython import *
import dateparser

args = demisto.args()
value = args.get('value')
begin = args.get('beginDate')
end = args.get('endDate')

inputTime = dateparser.parse(value)
startTime = dateparser.parse(begin)
endTime = dateparser.parse(end)

if inputTime < endTime and inputTime > startTime:
    demisto.results(True)
else:
    demisto.results(False)
