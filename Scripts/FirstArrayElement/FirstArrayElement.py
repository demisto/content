import demistomock as demisto

value = demisto.args()['value']

if isinstance(value, list) and value:
    VALUE = VALUE[0]

demisto.results(VALUE)
