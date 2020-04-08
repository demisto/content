import demistomock as demisto
from CommonServerPython import *
import dateparser

args = demisto.args()
value = args.get('value')
begin = args.get('beginTime')
end = args.get('endTime')

inputTime = dateparser.parse(value).time()
startTime = dateparser.parse(begin).time()
endTime = dateparser.parse(end).time()

if inputTime < endTime and inputTime > startTime:
    demisto.results(True)
else:
    demisto.results(False)
