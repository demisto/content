import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Searches the TIM DB for device indicators based on the provided query string and returns along with their custom fields.
"""


def search_indicators(query, max_size):
    result = []
    indicators = demisto.searchIndicators(
        query=query,
        size=max_size, page=0
    )

    for indicator in indicators.get("iocs"):
        indicator_dict = {
            "value": indicator.get("value"),
            "type": indicator.get("indicator_type")
        }

        if (indicator.get("CustomFields")):
            indicator_dict = {**indicator_dict, **indicator.get("CustomFields")}
            result.append(indicator_dict)

    return result


def main():
    query = demisto.args().get("query", "")
    max_size = arg_to_number(demisto.args().get("max", 1000))
    outputs = search_indicators(query, max_size)
    return_results(
        CommandResults(
            outputs_prefix="GetIndicatorCustomFieldsByQuery",
            outputs=outputs,
            readable_output=tableToMarkdown("Indicator Query Result", outputs)
        ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
