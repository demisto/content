from CommonServerPython import *


''' STANDALONE FUNCTION '''


def get_threat_indicator_list(args: Dict[str, Any]) -> list:
    """
    Executes cofense-threat-indicator-list command for given arguments.
    :type args: ``Dict[str, Any]``
    :param args: The script arguments provided by the user.

    :return: List of responses.
    :rtype: ``list``

    """

    # Fetch threat indicators based on threat value provided in the argument.
    # cofense-threat-indicator-list command will enrich the information based on value.
    threat_indicator = execute_command('cofense-threat-indicator-list',
                                       {'threat_value': f"{args.get('threat_value')}"},
                                       extract_contents=False)

    # Populate response
    return threat_indicator


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_threat_indicator_list(demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CofenseTriageThreatEnrichment. Error: {str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
