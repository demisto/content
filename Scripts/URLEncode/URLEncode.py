from urllib.parse import quote_plus

value = demisto.args()["value"]
processed_value = quote_plus(value)

eContext = {
    'EncodedURL': processed_value
}

entry = {'Type': entryTypes['note'],
         'Contents': eContext,
         'ContentsFormat': formats['json'],
         'HumanReadable': processed_value,
         'ReadableContentsFormat': formats['markdown'],
         'EntryContext': eContext}

demisto.results(entry)
