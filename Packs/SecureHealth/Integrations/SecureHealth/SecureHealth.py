import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
SecureHealth Integration example that is based off
HelloWorld Integration for Cortex XSOAR (aka Demisto).

This is a SYNTHETIC DATA DELIVERY MECHANISM ONLY designed to overcome the fact
that we don't hace access to a Palo Alto Networks firewall with AppID support.  This
integration delivers a SYNTHETIC DEVICE that creates an AppID like incident, listing the assetid of
possible compromise, IOC, etc.

In a real world, the incident would be generated off abnormal traffic patterns detected and generate an
incident for futher investigation.  The Playbook flow will combine manual and automatic processes.

Copyright © 2020 Seth Piezas for relevant code portions



Entry Point
-----------

This is the integration code entry point. It checks whether the ``__name__``
variable is ``__main__`` , ``__builtin__`` (for Python 2) or ``builtins`` (for
Python 3) and then calls the ``main()`` function. Just keep this convention.

"""


import json
import traceback
# import datetime
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import dateparser
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):

    def fetch(self, pageSize: int) -> List:
        results = self._http_request(
            method='GET',
            url_suffix='/fetch',
            params={
                'pageSize': pageSize
            }
        )
        events = results.get('events', [])
        return events


''' HELPER FUNCTIONS '''


def parse_domain_date(domain_date: Union[List[str], str], date_format: str = '%Y-%m-%dT%H:%M:%S.000Z') -> Optional[str]:
    """Converts whois date format to an ISO8601 string

    Converts the HelloWorld domain WHOIS date (YYYY-mm-dd HH:MM:SS) format
    in a datetime. If a list is returned with multiple elements, takes only
    the first one.

    :type domain_date: ``Union[List[str],str]``
    :param severity:
        a string or list of strings with the format 'YYYY-mm-DD HH:MM:SS'

    :return: Parsed time in ISO8601 format
    :rtype: ``Optional[str]``
    """

    if isinstance(domain_date, str):
        # if str parse the value
        return dateparser.parse(domain_date).strftime(date_format)
    elif isinstance(domain_date, list) and len(domain_date) > 0 and isinstance(domain_date[0], str):
        # if list with at least one element, parse the first element
        return dateparser.parse(domain_date[0]).strftime(date_format)
    # in any other case return nothing
    return None


def convert_to_demisto_severity(severity: str) -> int:
    """Maps HelloWorld severity to Cortex XSOAR severity

    Converts the HelloWorld alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the HelloWorld API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        'Low': 1,  # low severity
        'Medium': 2,  # medium severity
        'High': 3,  # high severity
        'Critical': 4   # critical severity
    }[severity]


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


# def test_module(client: Client, first_fetch_time: int) -> str:

#     try:
#         client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None, severity=None)
#     except DemistoException as e:
#         if 'Forbidden' in str(e):
#             return 'Authorization Error: make sure API Key is correctly set'
#         else:
#             raise e
#     return 'ok'

"""
SYNTHETIC INCIDIENT GENERATOR

"""


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], alert_status: Optional[str],
                    min_severity: str, alert_type: Optional[str]
                    ) -> Tuple[Dict[str, int], List[dict]]:

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    latest_created_time = cast(int, last_fetch)

    incidents: List[Dict[str, Any]] = []

    severity = ','.join(HELLOWORLD_SEVERITIES[HELLOWORLD_SEVERITIES.index(min_severity):])

    # alerts = [
    #     {"name": "test0", "severity": "Low", "ioc": "manygoodnews.com",
    #     "devicelocation": '1200 University Avenue, Berkeley Office', "deviceuuid": 'ab33819fcc01'}
    # ]
    alerts = client.fetch(1)

    for alert in alerts:
        incident_created_time = 1601022903.826247  # (datetime.datetime.now() -datetime.datetime(1970,1,1)).total_seconds()
        incident_created_time_ms = incident_created_time * 1000

        js = {
            "incidenttype": "DeviceDomainAccess",
            "assetID": "bakedasset",
            "ioc": {
                "type": "domain",
                "value": alert["ioc"]
            }
        }
        incident = {
            'name': alert["name"],
            'assetid': js["assetID"],
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(js),
            'severity': 4,
            'CustomFields': {  # Map specific XSOAR Custom Fields
                'deviceuuid': alert["deviceuuid"],
                'devicelocation': alert["devicelocation"],
                'ioc': alert["ioc"],
                'assetid': alert["deviceuuid"]
            }
        }

        incidents.append(incident)

        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    assert isinstance(first_fetch_time, int)

    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = None
        try:
            client = Client(
                base_url="https://us-central1-bynextmonday-4ffc3.cloudfunctions.net/securehealth/",
                headers=headers)
        except:
            msgs += "error unknown"
        if demisto.command() == 'test-module':
            print(client.fetch(1))

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = demisto.params().get('alert_status', None)
            alert_type = demisto.params().get('alert_type', None)
            min_severity = demisto.params().get('min_severity', None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_int(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                min_severity=min_severity,
                alert_type=alert_type
            )

            demisto.setLastRun(next_run)

            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
