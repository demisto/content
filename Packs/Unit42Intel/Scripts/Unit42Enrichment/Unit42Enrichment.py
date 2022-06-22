import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    ind_value = demisto.args().get('indicator')
    unit42_api_endpoint = "/unit42intel/indicator/import-and-enrich"

    try:
        if isinstance(ind_value, dict):
            indicator = ind_value
        else:
            indicator = demisto.executeCommand("findIndicators", {'value': ind_value})[0].get('Contents')[0]

        indicator_value = indicator.get('value')
        indicator_type = indicator.get('indicator_type')
        ind_payload = {'indicatorValue': indicator_value, 'indicatorType': indicator_type, 'onlyAutoFocus': True}
        response = demisto.executeCommand("demisto-api-post", {"uri": unit42_api_endpoint, "body": ind_payload})

        if is_error(response):
            error = f'Failed to enrich indicator {indicator_value} using Unit42 Threat Intelligence. Make sure that Unit42 license\
            is valid and Demisto REST API integration is enabled and properly configured.\n' + get_error(response)
            raise Exception(error)
        else:
            return_results(f'Indicator {indicator_value} has been successfully enriched with Unit42 Threat Intelligence')

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute Unit42Enrichment. Error: {str(ex)}')


'''ENTRY POINT'''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
