import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""DataminrPulseTransformExtractedIndicatorsToList Script for Cortex XSOAR (aka Demisto)."""


""" STANDALONE FUNCTION """


def flat_indicators(extracted_indicators: Dict) -> List:
    """Returns a python list of indicators with the information provided
    in the input (extracted_indicators).

    :type extracted_indicators: ``Dict``
    :param extracted_indicators: extracted indicators.

    :return: list of indicators
    :rtype: ``List``
    """
    flatten_indicators: List = []
    for values in extracted_indicators.values():
        for value in values:
            flatten_indicators.append(value)
    return flatten_indicators


""" COMMAND FUNCTION """


def transform_extracted_indicators_command(args: Dict[str, Any]) -> CommandResults:
    """Transform extracted indicators dictionary to list of indicators.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """

    extracted_indicators: Optional[str] = args.get("ExtractedIndicators", {})

    if not extracted_indicators:
        raise ValueError("ExtractedIndicators not specified")

    try:
        extracted_indicators = json.loads(extracted_indicators)
    except json.decoder.JSONDecodeError:
        raise DemistoException("Not able to parse the given parameter ExtractedIndicators")

    flatten_indicators: List = flat_indicators(extracted_indicators)  # type: ignore

    output = {"indicatorList": flatten_indicators}
    readable_output = "List of indicators\n\n{}".format(
        ", ".join([str(flatten_indicator) for flatten_indicator in flatten_indicators])
    )

    return CommandResults(
        outputs_prefix="TransformedIndicators", outputs_key_field="indicatorList", outputs=output, readable_output=readable_output
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(transform_extracted_indicators_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute TransformExtractedIndicatorsToList-DataminrPulse. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
