from datetime import datetime, timedelta
import json
import base64
import requests
from typing import (
    Dict,
    Any
)
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import traceback


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class Client(BaseClient):

    def correlation_alerts(self, dummy: str) -> Dict[str, str]:
        return self._http_request("POST", url_suffix="correlationalertswithlogs", data=dummy).text

    def correlations(self):
        return self._http_request("GET", data={}, full_url="http://172.17.6.41/api/service/correlations").text

    def baseintegration_dummy(self):
        return self._http_request("GET", url_suffix="correlations", data={}).text

''' HELPER FUNCTIONS '''



''' COMMAND FUNCTIONS '''
def baseintegration_dummy_command(client: Client):
    result = client.correlations()

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )
def correlations_command(client: Client):
    result = client.correlations()

    return CommandResults(
        outputs_prefix='Correlations',
        outputs_key_field='',
        outputs=result,
    )


def correlation_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    if args.get('startDate') is None:
        raise Exception("Must have this argument")
    elif args.get('endDate') is None:
        raise Exception("Must have this argument")
    
    parameters = {
        'startDate': args.get('startDate'),
        'endDate':args.get('startDate'),
        'showSolved':args.get('showSolved', False),
        'crrPluginId': args.get('crrPluginId', -1),
        'containStr':args.get('containStr', None),
        'risk':args.get('risk', -1),
        'srcIPPort':args.get('srcIPPort', None),
        'destIPPort':args.get('destIPPort', None),
        'srcPort':args.get('srcPort', None),
        'destPort':args.get('destPort', None),
        'riskOperatorID':args.get('riskOperatorID', "equal"),
        'isJsonLog': True
    }


    # Call the Client function and get the raw response
    result = client.correlation_alerts(json.dumps(parameters))

    return CommandResults(
        outputs_prefix='CorrelationAlerts',
        outputs_key_field='',
        outputs=result,
    )


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        if client.correlations().get('StatusCode') == 200:
            message = 'ok'
        else:
            raise Exception(f"StatusCode: {client.correlations().get('StatusCode')}, Error: {client.correlations().get('ErrorMessage')}")
    except DemistoException as e:
        if '401' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API User and Password is correctly set'
        else:
            raise e
    return message


''' INCIDENT '''

def fetch_incidents(client: Client, args: Dict[str, Any]):
    BeginDate=0
    EndDate=0
    events=list()
    if len(demisto.getLastRun())==0:
        BeginDate=datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        EndDate=((datetime.now() + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S"))

    else:
        Begindate=demisto.getLastRun()
        EndDate=(datetime.strptime(demisto.getLastRun(),"%Y-%m-%dT%H:%M:%S") + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")

    demisto.setLastRun(EndDate)
    incidentsResult = correlation_alerts_command(client, args)
    if incidentsResult.get("StatusCode") == 200:
        for i in incidentsResult.get("Data"):
            if len(i) != 0:
                events.append({'name': i['Name'], 'create_time': i['CreatedDate'],
                                'event_id': i['CorrelationID'], 'labels': [{'type': 'Cryptech'}], 'rawJSON': json.dumps(i)})
    demisto.incidents(events)

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    authorization = params.get('credentials').get('identifier') + ":" + params.get('credentials').get('password')
    auth_byte= authorization.encode('utf-8')
    base64_byte = base64.b64encode(auth_byte)
    base64_auth = base64_byte.decode('utf-8')
    authValue = "Basic " + base64_auth 

    headers = {
        "Content-Type": "application/json",
        'Authorization': authValue
    }
    # get the service API url
    base_url = urljoin(params.get('url'), '/api/service/')
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            verify=False,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'cryptosim-get-correlations':
            return_results(correlations_command(client))
 
        elif demisto.command() == 'cryptosim-get-correlation-alerts':
            return_results(correlation_alerts_command(client, demisto.args()))
        
        elif demisto.command() == 'cryptosim-fetch-incidents':
            fetch_incidents(client, demisto.args())

    
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()