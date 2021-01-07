import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import json


def fetch_indicators_mock():
    indicators = []
    for i in range(10000):
        url = 'www.google' + str(randint(0, 1000)) + '.com'
        indicators.append({
            "value": url,
            "rawJSON": {
                "type": "URL",
                "source": "my feed"
            }
        })
    return indicators


if demisto.command() == 'fetch-indicators':
    indicators = fetch_indicators_mock()

    demisto.createIndicators(indicators)

    # important (!) this is an ack to let the server know that we finished the fetch
    demisto.results("done")
    sys.exit(0)
