import demistomock as demisto
from CommonServerPython import *

from anyrun.connectors import LookupConnector
from anyrun import RunTimeException

VERSION = 'PA-XSOAR:2.0.0'


def test_module(params: dict) -> str:
    """ Performs ANY.RUN API call to verify integration is operational """
    with LookupConnector(get_authentication(params)) as connector:
        connector.check_authorization()
        return 'ok'


def get_authentication(params: dict) -> str:
    """
    Builds API verification data using demisto params

    :param params: Demisto params
    :return: API-KEY verification string
    """
    return f"API-KEY {params.get('anyrun_api_key')}"


def get_intelligence(params: dict, args: dict) -> None:
    """
    Initialize TI Lookup search

    :param params: Demisto params
    :param args: Demisto args
    """
    with LookupConnector(
        get_authentication(params),
        integration=VERSION
    ) as connector:
        intelligence = connector.get_intelligence(**args)

    command_results = CommandResults(
        outputs_prefix='ANYRUN.Lookup',
        outputs=intelligence,
        ignore_auto_extract=True
    )

    return_results(command_results)


def main():
    """ Main Execution block """
    params = demisto.params()
    args = demisto.args()
    handle_proxy()

    try:
        if demisto.command() == 'anyrun-get-intelligence':
            get_intelligence(params, args)
        elif demisto.command() == 'test-module':
            result = test_module(params)
            return_results(result)
        else:
            return_results(f'Command {demisto.command()} is not implemented in ANY.RUN')
    except RunTimeException as exception:
        return_error(exception.description, error=str(exception.json))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
