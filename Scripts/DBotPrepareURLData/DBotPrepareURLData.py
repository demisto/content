import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import uuid
import pickle
import collections

BAD_SCORE = 3
GOOD_SCORE = 1

MAX_INDICATORS = demisto.args()['maxIndicators']
res = demisto.executeCommand("findIndicators", {'query': demisto.args()['query'],
                                                'size': MAX_INDICATORS})
if is_error(res):
    return_error("Error query indicators")
indicators = res[0]['Contents']
indicators = sorted(indicators, key=lambda x: x['firstSeen'])
urls = collections.OrderedDict()
count_good = 0
count_bad = 0
for i in indicators:
    if i['score'] == BAD_SCORE:
        count_bad += 1
        score = 1
    elif i['score'] == GOOD_SCORE:
        count_good += 1
        score = 0
    else:
        continue
    urls[i['value']] = score

filename = str(uuid.uuid4()) + ".pickle"
demisto.results(fileResult(filename, pickle.dumps(urls)))
demisto.results({
    'Type': entryTypes['note'],
    'Contents': urls,
    'ContentsFormat': formats['json'],
    'ReadableContentsFormat': formats['markdown'],
    'HumanReadable': "Success query %d urls: %d Valid, %d Malicious" % (len(urls), count_good, count_bad),
    'EntryContext': {
        'DBotURLFileName': filename
    }
})
