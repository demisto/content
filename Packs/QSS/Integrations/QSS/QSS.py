import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):

    def search_alerts(self, alert_status: Optional[str], severity: Optional[str],
                      alert_type: Optional[str], max_results: Optional[int],
                      start_time: Optional[int]) -> List[Dict[str, Any]]:

        request_params: Dict[str, Any] = {}

        api_key = demisto.params().get('apikey')

        if api_key:

            request_params['apikey'] = api_key

        duration = demisto.params().get('duration')
        if duration:
            request_params['duration'] = duration

        severity = demisto.params().get('severity')
        if severity:
            request_params['severity'] = severity

        status = demisto.params().get('status')
        if status:
            request_params['status'] = status

        false_positive = demisto.params().get('false_positive')
        if false_positive:
            request_params['false_positive'] = false_positive

        demisto.debug(f'Command being called is {demisto.command()}')

        return self._http_request(
            method='GET',
            url_suffix='',
            params=request_params
        )


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: str) -> int:

    
    return {
        'Low': 1,  # low severity
        'Medium': 2,  # medium severity
        'High': 3,  # high severity
        'Critical': 4   # critical severity
    }[severity]


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:

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

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        
        return int(arg)
    if isinstance(arg, str):
        
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
           
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
         
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


''' COMMAND FUNCTIONS '''


def test_module(client: Client, first_fetch_time: int) -> str:

    try:
        client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None, severity=None)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], alert_status: Optional[str],
                    min_severity: str, alert_type: Optional[str]
                    ) -> Tuple[Dict[str, int], List[dict]]:

    
    last_fetch = last_run.get('last_fetch', None)

   
    if last_fetch is None:

       
        last_fetch = first_fetch_time

    else:

       
        last_fetch = int(last_fetch)

     

    latest_created_time = cast(int, last_fetch)

     
    incidents: List[Dict[str, Any]] = []
 

    alerts = client.search_alerts(
        alert_type=alert_type,
        alert_status=alert_status,
        max_results=max_results,
        start_time=last_fetch,
        severity=''
    )

    demisto.debug("Alerts Fetched")

    for alert in alerts:
        
        incident_created_time = int(alert.get('created_sec', '0'))

         
        if last_fetch:
            if incident_created_time <= last_fetch:
                continue
 
        incident_name = 'SOC Case ' + alert['reference']

        demisto.debug("JSON debug alert")
        demisto.debug(json.dumps(alert))
        incident = {
            'name': incident_name,
            'occurred': alert.get('created'),
            'event_id': alert.get('id'),
            'rawJSON': json.dumps(alert),
            'severity': convert_to_demisto_severity(alert.get('severity', 'Low')),

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

     
    base_url = urljoin(demisto.params()['url'], '')

     
    verify_certificate = not demisto.params().get('insecure', False)

    
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
            # 'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, first_fetch_time)
            return_results(result)

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

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to crate
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
