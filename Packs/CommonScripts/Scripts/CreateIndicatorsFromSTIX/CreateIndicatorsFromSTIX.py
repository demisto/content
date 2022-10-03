import demistomock as demisto
from CommonServerPython import *


def parse_indicators_using_stix_parser(entry_id):
    """ Parse Indicators using StixParserV2.

    :param entry_id: the uploaded file for the script
    :return: parsed indicators in stix Parser
    """
    if not entry_id:
        return_error(f"Could not find file for entry id {entry_id}.")
    comm_output = demisto.executeCommand("StixParserV2", {"entry_id": entry_id})
    indicators = comm_output[0].get("Contents")
    if is_error(comm_output[0]):
        return_error(indicators)
    return indicators


def create_indicators_loop(indicators):
    """ Create indicators using createNewIndicator automation

    :param indicators: parsed indicators
    :return: errors if exist
    """
    errors = list()
    for indicator in indicators:
        res = demisto.executeCommand("createNewIndicator", indicator)
        if is_error(res[0]):
            errors.append(f'Error creating indicator - {(res[0]["Contents"])}')
    return_outputs(
        f"Create Indicators From STIX: {len(indicators) - len(errors)} indicators were created."
    )
    return errors


def main():     # pragma: no cover
    args = demisto.args()
    entry_id = args.get("entry_id", "")
    indicators = parse_indicators_using_stix_parser(entry_id)
    errors = create_indicators_loop(indicators)
    if errors:
        return_error(json.dumps(errors, indent=4))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
