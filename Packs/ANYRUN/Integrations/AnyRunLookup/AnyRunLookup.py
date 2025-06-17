import traceback
from typing import Callable, Any

import demistomock as demisto
from CommonServerPython import *

from anyrun.connectors import LookupConnector
from anyrun import RunTimeException

def test_module(params: dict) -> str:
    """ Performs ANY.RUN API call to verify integration is operational """
    with LookupConnector(get_authentication(params)) as connector:
        connector.check_authorization()
        return 'ok'


def handle_exceptions(function: Callable) -> Any:
    """
    Handles all exception, formats them, then sends to WarRoom

    :param function: Wrapped function
    """
    def wrapper(*args, **kwargs) -> Any:
        try:
            return function(*args, **kwargs)
        except RunTimeException as exception:
            return_error(exception.description, error=str(exception.json))
        except Exception:
            exception = str(traceback.format_exc())
            return_error(exception, error=exception)

    return wrapper


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


@handle_exceptions
def main():
    """ Main Execution block """
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    handle_proxy()

    match command:
        case 'anyrun-get-intelligence':
            get_intelligence(params, args)
        case 'test-module':
            return_results(test_module(params))
        case _:
            raise NotImplementedError(f'Command {command} is not implemented in ANY.RUN')


if __name__ in ['__main__', 'builtin', 'builtins']:
    VERSION = 'PA-XSOAR:2.0.0'
    main()
