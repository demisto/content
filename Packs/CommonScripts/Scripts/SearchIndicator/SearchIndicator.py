import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def search_indicators(args):
    # search for indicators
    indicators = demisto.executeCommand("findIndicators", {"query": args.get("query"), "size": args.get("size")})[0][
        "Contents"]

    # return specific information for found indicators
    filtered_indicators = []
    fields = ['id', 'indicator_type', 'value', 'score']
    if args.get("add_fields_to_context"):
        fields = fields + args.get("add_fields_to_context").split(",")
        fields = [x.strip() for x in fields]  # clear out whitespace
    for indicator in indicators:
        style_indicator = {}
        for field in fields:
            style_indicator[field] = indicator.get(field, indicator.get("CustomFields", {}).get(field, "n/a"))
        style_indicator["verdict"] = scoreToReputation(style_indicator['score'])
        filtered_indicators.append(style_indicator)

    headers = fields + ["verdict"]
    markdown = tableToMarkdown("Indicators Found", filtered_indicators, headers)
    return markdown, filtered_indicators


def main():
    args = demisto.args()
    try:
        readable_output, outputs = search_indicators(args)
        results = CommandResults(
            outputs_prefix='foundIndicators',
            outputs_key_field='id',
            readable_output=readable_output,
            outputs=outputs,
            ignore_auto_extract=True
        )
        return_results(results)
    except DemistoException as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
