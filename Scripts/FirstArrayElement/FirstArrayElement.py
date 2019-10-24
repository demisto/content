import demistomock as demisto

value = demisto.args()['value']

if isinstance(value, list) and value:
    value = value[0]

demisto.results(value)
