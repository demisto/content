import demistomock as demisto

VALUE = demisto.args()['value']

if type(VALUE) is list and len(VALUE) > 0:
    VALUE = VALUE[-1]

demisto.results(VALUE)
