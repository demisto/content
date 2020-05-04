import demistomock as demisto

args = demisto.args()
value = args.get("value")
if value and isinstance(value, list):
    demisto.results(value)
elif value:
    demisto.results([value])
else:
    demisto.results([])
