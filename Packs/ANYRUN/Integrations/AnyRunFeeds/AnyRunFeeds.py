import traceback
from base64 import b64encode
from typing import Callable, Any

import demistomock as demisto
import requests
from CommonServerPython import *

from anyrun.connectors import FeedsConnector
from anyrun.iterators import FeedsIterator
from anyrun import RunTimeException


def test_module(params: dict) -> str:
    """ Performs ANY.RUN API call to verify integration is operational """
    with FeedsConnector(get_authentication(params)) as connector:
        connector.check_authorization()
        return 'Successfully connected to ANY.RUN Threat Intelligence Feeds.'


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
    username = params.get('username')
    password = params.get('password')

    if username == '_token':
        return_error('You should use Basic verification to access ANY.RUN Feeds service')

    user_credits = f'{username}:{password}'.encode('utf-8')
    auth = 'Basic ' + b64encode(user_credits).decode()

    return auth


def extract_indicator_data(indicator: dict) -> tuple[str, str]:
    """
    Extracts indicator type, value using raw indicator

    :param indicator: Raw ANY.RUN indicator
    :return: ANY.RUN indicator type, ANY.RUN indicator value
    """
    pattern = indicator.get("pattern")
    indicator_type = pattern.split(':')[0][1:]
    indicator_value = pattern.split(" = '")[1][:-2]

    return indicator_type, indicator_value


def get_indicators(params: dict, args: dict) -> None:
    indicators: list[dict[str, str]] = []

    fqdn = params.get('soar_fqdn')
    api_key_id = params.get('soar_api_key_id')
    api_key = params.get('soar_api_key')

    url = f'https://{fqdn}/xsoar/public/v1/indicator/create'
    headers = {
        'Authorization': api_key,
        'x-xdr-auth-id': api_key_id
    }

    with FeedsConnector(
        get_authentication(params),
        integration=VERSION
    ) as connector:
        for indicator in FeedsIterator.taxii_stix(connector, **args):
            if indicator.get('type') == 'identity':
                continue

            indicator_type, indicator_value = extract_indicator_data(indicator)
            indicator_type = {'ipv4-addr': 'Ip', 'url': 'URL', 'domain-name': 'Domain'}.get(indicator_type)

            payload = {
                "indicator": {
                    "indicator_type": indicator_type,
                    "value": indicator_value,
                    "score": 3,
                    "vendor": "ANY.RUN",
                    "CustomFields": {
                        "vendor": "ANY.RUN",
                        "service": "ANY.RUN TI Feeds"
                    }
                }
            }

            requests.post(url, headers=headers, json=payload)
            indicators.append({'type': indicator_type, 'value': indicator_value, 'verdict': 'Malicious'})

        return_results(
            CommandResults(
                readable_output=tableToMarkdown(
                    'Indicators from ANY.RUN TI Feed',
                    indicators,
                    headers=['type', 'value', 'verdict'],
                    headerTransform=string_to_table_header

                ),
                ignore_auto_extract=True
            )
        )


@handle_exceptions
def main():
    """ Main Execution block """
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    handle_proxy()

    match command:
        case 'anyrun-get-indicators':
            get_indicators(params, args)
        case 'test-module':
            return_results(test_module(params))
        case _:
            raise NotImplementedError(f'Command {command} is not implemented in ANY.RUN')


if __name__ in ['__main__', 'builtin', 'builtins']:
    VERSION = 'PA-XSOAR:2.0.0'
    main()
