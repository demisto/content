import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import json


def fetch_indicators_mock():
    indicators = []

    for i in range(2):
        if i == 0:
            indicators.append({
                "value": "www.google.com",
                "rawJSON": {
                    "type": "myURL",
                    "myTag": "URL value B",
                    "source": "my feed"
                }
            }
            )
        elif i == 1:
            indicators.append({
                "value": "1.2.3.4",
                "rawJSON": {
                    "type": "myIP",
                    "myTag": "IP value B",
                    "source": "my feed"
                }
            }
            )

    return indicators


if demisto.command() == 'fetch-indicators':
    indicators = fetch_indicators_mock()

    demisto.createIndicators(indicators)

    # important (!) this is an ack to let the server know that we finished the fetch
    demisto.results("done")
    sys.exit(0)
