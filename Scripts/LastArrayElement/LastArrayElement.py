import demistomock as demisto

value = demisto.args()['value']

if type(value) is list and len(value) > 0:
    value = value[-1]

demisto.results(value)
