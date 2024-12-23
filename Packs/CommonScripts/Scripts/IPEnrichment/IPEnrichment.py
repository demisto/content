import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import socket


def search_indicator(ip: str):
    # search for indicators
    indicators = demisto.executeCommand("findIndicators", {"query": ip, "size": 1})[0]["Contents"]  #todo: is size mandatory?

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

    # headers = fields + ["verdict"]
    # markdown = tableToMarkdown("Indicators Found", filtered_indicators, headers)
    return filtered_indicators


def ip_enrichment(ip: str, third_enrichment: bool, verbose: bool) -> CommandResults:
    # Check if the indicator exist in TIM
    #Internal \ external
    #Check prevalence
    #IP
    #get-endpoint-data

    output = None
    md = tableToMarkdown('IP Enrichment', [output])

    return CommandResults(
        outputs=output,
        # outputs_prefix='Endpoint',
        # outputs_key_field='Hostname',
        readable_output=md,
    )


def main():
    try:
        ip = demisto.args().get('ip', '')
        third_enrichment = demisto.args().get('3rd_enrichment', False)
        verbose = demisto.args().get('verbose', False)
        return_results(ip_enrichment(ip, third_enrichment, verbose))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'IP Enrichment failed. Error information: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
