import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import json

IPs_list = ['43.2.52.175', '153.74.7.71', '13.96.60.251', '100.13.173.12']

lastRun = demisto.getLastRun()


def fetch_indicators_mock():
    indicators = []

    for i in range(len(IPs_list)):
        value = IPs_list[i]

        if i == 0:
            indicators.append({
                "score": 0,
                "value": value,
                "type": "IP",
                "rawJSON": {
                    "value": value,
                    "myShortText": "111",
                    "myMultiSelect": "aaa"
                }
            }
            )
        else:
            indicators.append({
                "score": 0,
                "value": value,
                "type": "IP",
                "rawJSON": {
                    "value": value,
                    "myShortText": "333",
                    "myMultiSelect": "ccc"
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
