import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

batch_size = demisto.args()['batch_size']
list_of_items = demisto.args()['data']
context_path = demisto.args()['context_path']

list_of_items = list(list_of_items.split(","))

batch_size = int(batch_size)
batch_list = []

for i in range(0, len(list_of_items), batch_size):
    batch_list.append(list_of_items[i:i + batch_size])

context = {"BatchedData": {context_path: batch_list}}
demisto.results({'Type': entryTypes['note'],
                 'Contents': context,
                 'ContentsFormat': formats['json'],
                 'EntryContext': context})
