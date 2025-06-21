import traceback
from typing import Callable, Any
from datetime import datetime

import demistomock as demisto
from CommonServerPython import *

from anyrun.connectors import FeedsConnector
from anyrun.iterators import FeedsIterator
from anyrun import RunTimeException

DATE_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

def test_module(params: dict) -> str:
    """ Performs ANY.RUN API call to verify integration is operational """
    with FeedsConnector(params.get('anyrun_auth_token')) as connector:
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


def get_timestamp(params: dict) -> str:
    """
    Extracts actual fetch timestamp

    :param params: Demisto params
    :return: Fetch timestamp
    """
    if demisto.getLastRun():
        return demisto.getLastRun().get('next_fetch')
    return params.get('modified_after')

def update_timestamp(new_timestamp: datetime | None) -> None:
    """
    Updates fetch timestamp if exists

    :param new_timestamp: New generated fetch timestamp
    """
    if new_timestamp:
        if demisto.getLastRun():
            actual_timestamp = datetime.strptime(demisto.getLastRun().get('next_fetch'), DATE_TIME_FORMAT)

            if new_timestamp > actual_timestamp:
                demisto.setLastRun({'next_fetch': new_timestamp.strftime(DATE_TIME_FORMAT)})
        else:
            demisto.setLastRun({'next_fetch': new_timestamp.strftime(DATE_TIME_FORMAT)})

def convert_indicators(indicators: list[dict]) -> list[dict]:
    """
    Converts ANY.RUN indicator to XSOAR indicator format

    :param indicators: ANY.RUN indicator
    :return: XSOAR indicator
    """
    converted_indicators: list[dict] = []

    for indicator in indicators:
        indicator_type, indicator_value = extract_indicator_data(indicator)

        indicator_payload = {
            "value": indicator_value,
            "type": {'ipv4-addr': 'Ip', 'url': 'URL', 'domain-name': 'Domain'}.get(indicator_type),
            "fields": {
                "firstseenbysource": indicator.get("created"),
                "first_seen": indicator.get("created"),
                "modified": indicator.get("modified"),
                "last_seen": indicator.get("modified"),
                "vendor": "ANY.RUN",
                "source": "ANY.RUN TI Feeds"
            }
        }

        converted_indicators.append(indicator_payload)

    return converted_indicators

def fetch_indicators_command(params: dict) -> None:
    """
    Initializes the update of indicators

    :param params: Demisto params
    """
    modified_after = get_timestamp(params)

    with FeedsConnector(
        params.get('anyrun_auth_token'),
        integration=VERSION
    ) as connector:
        connector._taxii_delta_timestamp = None
        for chunk in FeedsIterator.taxii_stix(
            connector,
            match_type='indicator',
            match_version='all',
            modified_after=modified_after,
            limit=10000,
            chunk_size=10000
        ):
            demisto.createIndicators(convert_indicators(chunk))

        update_timestamp(connector._taxii_delta_timestamp)


@handle_exceptions
def main():
    """ Main Execution block """
    command = demisto.command()
    params = demisto.params()

    handle_proxy()

    match command:
        case 'fetch-indicators':
            fetch_indicators_command(params)
        case 'test-module':
            return_results(test_module(params))
        case _:
            raise NotImplementedError(f'Command {command} is not implemented in ANY.RUN')


if __name__ in ['__main__', 'builtin', 'builtins']:
    VERSION = 'PA-XSOAR:2.0.0'
    main()
