from typing import Tuple

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

stix_struct_to_indicator = {
    "CVE CVSS Score": FeedIndicatorType.CVE,
    "File": FeedIndicatorType.File,
    "Domain": FeedIndicatorType.Domain,
    "Email": FeedIndicatorType.Email,
    "Registry Path Reputation": FeedIndicatorType.Registry,
    "URL": FeedIndicatorType.URL,
    "Username": FeedIndicatorType.Account
}
"""
    "CVE CVSS Score": [],
    "File": [],
    "IP": [],
    "Domain": [],
    "Email": [
      "user@example.com"
    ],
    "Registry Path Reputation": ["HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\RKey"],
    "URL": [
      "http://demisto.com"
    ]
  }"""


def build_indicators(data):
    # type: (list) -> list
    return [
        {
            "type": stix_struct_to_indicator.get(indicator.get("indicator_type")),
            "value": indicator.get("value"),
            "rawJSON": indicator
        }
        for indicator in data
        if stix_struct_to_indicator.get(indicator.get("indicator_type"))
    ]


def main():
    args = demisto.args()
    entry_id = args.get("entry_id", "")
    file_path = demisto.getFilePath(entry_id).get('path')
    demisto.results(file_path)
    if not file_path:
        return_error("Could not find file for entry id {}.".format(entry_id))
    with open(file_path) as file:
        file_txt = file.read()
    demisto.results(file_txt)
    results = demisto.executeCommand("STIXParser", {"iocXml": file_txt})
    data = json.loads(results)
    demisto.results(data)
    indicators = build_indicators(data)
    for b in batch(indicators, 2000):
        demisto.createIndicators(b)
    return_outputs("Create Indicators From STIX: {} were created.".format(len(indicators)))


if __name__ in ("builtin",):
    main()
