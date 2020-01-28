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
    """

    Args:
        data: list of StixParser output


    Returns:
        list of indicators

    Examples:
        >>> build_indicators([{"indicator_type": "Domain", "value": "example.com", "score": 5}])
        [{'type': 'Domain', 'value': 'example.com', 'rawJSON': {'indicator_type': 'Domain', 'value': 'example.com', \
'score': 5}}]
    """
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
    if not file_path:
        return_error("Could not find file for entry id {}.".format(entry_id))
    with open(file_path) as file:
        file_txt = file.read()

    contents = demisto.executeCommand("StixParser", {"iocXml": file_txt})[0].get("Contents")
    data = json.loads(contents)
    indicators = build_indicators(data)

    errors = list()
    for indicator in indicators:
        res = demisto.executeCommand('createNewIndicator', indicator)
        if is_error(res[0]):
            errors.append("Error creating indicator - {}".format(res[0]['Contents']))
    return_outputs("Create Indicators From STIX: {} indicators were created.".format(len(indicators) - len(errors)))
    if errors:
        return_error(str(errors))


if __name__ in ("builtins",):
    main()
