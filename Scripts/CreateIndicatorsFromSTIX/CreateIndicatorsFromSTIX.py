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


def build_indicators(data: list) -> list:
    return [
        {
            "type": stix_struct_to_indicator.get(indicator.get("indicator_type")),
            "value": indicator.get("value"),
            "rawJSON": indicator
        }
        for indicator in data
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

    contents = demisto.executeCommand("StixParser", {"iocXml": file_txt})[0].get("Contents")
    data = json.loads(contents)
    indicators = build_indicators(data)

    for part in batch(indicators, 2000):
        demisto.createIndicators(part)
    return_outputs("Create Indicators From STIX: {} were created.".format(len(indicators)))


if __name__ in ("builtins",):
    main()
