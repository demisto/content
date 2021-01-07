import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import json

tags = demisto.params()["tags"]


def fetch_indicators_mock():
    indicators = []
    for i in range(10):
        ip = str(randint(0, 254)) + '.' + str(randint(0, 254)) + '.' + str(randint(0, 254)) + '.' + str(randint(0, 254))
        url = 'www.google' + str(randint(0, 10000)) + '.com'
        if (i % 2) == 0:
            indicators.append({
                "value": url,
                "rawJSON": {
                    "type": "URL",
                    "tags": tags,
                    "source": "my feed"
                }
            }
            )
        elif (i % 2) > 0:
            indicators.append({
                "value": ip,
                "rawJSON": {
                    "myHTML": "<script>alert()</script><h2>daud</h2>",
                    "type": "IP",
                    "tags": "IP value B",
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
