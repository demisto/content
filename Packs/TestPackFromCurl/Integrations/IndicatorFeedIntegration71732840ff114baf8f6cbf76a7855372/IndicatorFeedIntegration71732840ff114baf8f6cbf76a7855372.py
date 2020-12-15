import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import json

IPs_list = ['254.84.192.176', '253.250.244.115', '199.213.22.192', '135.81.117.4']

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
