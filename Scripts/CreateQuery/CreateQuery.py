import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

ARGS = demisto.args()
NUM_OF_FILTERS = 8

query = []
for i in range(0, NUM_OF_FILTERS):
    filter_number = i + 1
    field = ARGS.get(f'field_{filter_number}')
    operator = ARGS.get(f'operator_{filter_number}')
    value = ARGS.get(f'value_{filter_number}')
    if field and operator and value:
        query_filter = [field, operator, value]
        query.append(query_filter)

query = json.dumps(query)
md = f'### Your query string is:\n {query}'
demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['text'],
    'Contents': query,
    'EntryContext': {'QueryString(val == obj)': query},
    'HumanReadable': md
})
