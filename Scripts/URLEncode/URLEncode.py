import demistomock as demisto
from CommonServerPython import *
from urllib.parse import quote_plus


def urlencode(value):
    encoded_url = quote_plus(value)

    return_outputs(encoded_url, {'EncodedURL': encoded_url}, encoded_url)
    return (encoded_url, {'EncodedURL': encoded_url}, encoded_url)


if __name__ in ('__builtin__', 'builtins'):
    urlencode(demisto.getArg('value'))
