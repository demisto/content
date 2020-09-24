import demistomock as demisto
from CommonServerPython import *  # noqa: F401

original_object = demisto.args()['original_object']
key_to_update = demisto.args()['key_to_update']
values = demisto.args()['values']
index = int(demisto.args().get('index', '-1'))
context_key = demisto.args().get('context_key', 'UpdatedObject')

if not isinstance(values, list):
    values = values.split(',')

if index != -1:
    original_object[index][key_to_update] = values[0]
else:
    for idx, (obj, val) in enumerate(zip(original_object, values)):
        original_object[idx][key_to_update] = val

ctx = {
    context_key: original_object
}

demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['json'],
    'Contents': original_object,
    'EntryContext': ctx
})
