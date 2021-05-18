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
    "Username": FeedIndicatorType.Account,
}


def score_to_reputation(score):
    """
       Converts score (in number format) to human readable reputation format

       :type score: ``int``
       :param score: The score to be formatted (required)

       :return: The formatted score
       :rtype: ``str``
    """
    to_str = {3: "Bad", 2: "Suspicious", 1: "Good", 0: "None"}
    return to_str.get(score, "None")


def main():
    args = demisto.args()
    entry_id = args.get("entry_id", "")
    file_path = demisto.getFilePath(entry_id).get("path")
    if not file_path:
        return_error("Could not find file for entry id {}.".format(entry_id))
    with open(file_path) as file:
        file_txt = file.read()

    comm_output = demisto.executeCommand("StixParser", {"iocXml": file_txt})
    contents = comm_output[0].get("Contents")
    if is_error(comm_output[0]):
        return_error(contents)
    data = json.loads(contents)
    indicators = [
        {
            "type": stix_struct_to_indicator.get(indicator.get("indicator_type")),
            "value": indicator.get("value"),
            "reputation": score_to_reputation(indicator.get("score")),
            "source": indicator.get("CustomFields", {}).get("stixPackageId", "STIX Bundle"),
            "rawJSON": indicator,
        }
        for indicator in data
    ]
    errors = list()
    for indicator in indicators:
        res = demisto.executeCommand("createNewIndicator", indicator)
        if is_error(res[0]):
            errors.append("Error creating indicator - {}".format(res[0]["Contents"]))
    return_outputs(
        "Create Indicators From STIX: {} indicators were created.".format(
            len(indicators) - len(errors)
        )
    )
    if errors:
        return_error(json.dumps(errors, indent=4))


if __name__ in ("builtins",):
    main()
