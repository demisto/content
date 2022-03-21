import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

dArgs = demisto.args()
question_filters = "Index Query File Details"

sensors = dArgs.get("sensors")
del dArgs['sensors']

filter_type = None
filter_value = None

if 'filter_type' in dArgs:
    filter_type = dArgs.get('filter_type')
    del dArgs['filter_type']

if 'filter_value' in dArgs:
    filter_value = dArgs.get('filter_value')
    del dArgs['filter_value']

params = []
for key in dArgs:
    params.append(key + "=" + dArgs[key])

if len(params) > 0:
    question_filters = question_filters + "{" + ','.join(params) + "}"

if filter_type is not None:
    question_filters = question_filters + ",that " + filter_type + ":" + filter_value

demisto.results(demisto.executeCommand('tn-ask-manual-question', {'sensors': sensors, 'question_filters': question_filters}))
