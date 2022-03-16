from datetime import datetime, timedelta
from CommonServerPython import *
from CommonServerUserPython import *
import traceback
import json
import base64
import requests
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class Client(BaseClient):

    def correlation_alerts(self):
        args = demisto.args()
        endTime = datetime.now()
        startTime = endTime - timedelta(minutes=demisto.params().get('incidentFetchInterval', 360))
        parameters = {
            'startDate': args.get('startDate', startTime.isoformat()),
            'endDate': args.get('endDate', endTime.isoformat()),
            'showSolved': args.get('showSolved', False),
            'crrPluginId': args.get('crrPluginId', -1),
            'containStr': args.get('containStr', None),
            'risk': args.get('risk', -1),
            'srcIPPort': args.get('srcIPPort', None),
            'destIPPort': args.get('destIPPort', None),
            'srcPort': args.get('srcPort', None),
            'destPort': args.get('destPort', None),
            'riskOperatorID': args.get('riskOperatorID', "equal"),
            "isJsonLog": True
        }

        return self._http_request("POST", url_suffix="correlationalertswithlogs",
                                    data=json.dumps(parameters))

    def correlations(self):
        return self._http_request("GET", data={}, url_suffix="correlations")


''' COMMAND FUNCTIONS '''


def correlations_command(client: Client):
    result = client.correlations()

    return CommandResults(
        outputs_prefix='Correlations',
        outputs_key_field='',
        outputs=result,
    )


def correlation_alerts_command(client: Client):

    # Call the Client function and get the raw response
    result = client.correlation_alerts()

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
            raise Exception(f"""StatusCode: 
                            {client.correlations().get('StatusCode')}, 
                            Error: {client.correlations().get('ErrorMessage')}
                            """)
    except DemistoException as e:
        if '401' in str(e):
            message = 'Authorization Error: make sure API User and Password is correctly set'
        else:
            raise e
    return message


''' INCIDENT '''


def fetch_incidents(client: Client):

    max_results = arg_to_number(arg=demisto.params().get('max_fetch'), arg_name='max_fetch', required=False)


    first_fetch_time = arg_to_datetime(demisto.params().get('first_fetch')).isoformat()

    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch', first_fetch_time)

    incidentsList=[]
    alert_response = client.correlation_alerts()
    incident_data = alert_response['Data']

    for inc in incident_data:

        if len(incidentsList) > max_results:
            break

        incident_name = inc['CorrelationAlert']['NAME']
        time_stamp = inc['CorrelationAlert']['CREATEDATE']+"Z"

        severity_level = int(inc['CorrelationAlert']['RISK'])
        if severity_level >=0 and severity_level <= 5:
            severity = 1
        elif severity_level > 5 and severity_level <= 7:
            severity = 2
        elif severity_level > 7 and severity_level <= 9:
            severity = 3
        elif severity_level > 9 and severity_level <= 10:
            severity = 4
        else:
            severity = 0

        # "log" column is stringfyed 'Log' data.
        inc['Log'].pop("log")

        incident_object = {**inc['Log'], **inc['CorrelationAlert']}

        incident = {
            'name': incident_name,
            'occurred': time_stamp,
            'rawJSON': json.dumps(incident_object),
            "severity": severity,
            'type': 'Crpyotsim CorrelationAlert'
        }

        incidentsList.append(incident)
        
        created_incident = datetime.strptime(time_stamp, DATE_FORMAT)
        last_fetch = datetime.strptime(last_fetch,DATE_FORMAT)
        if created_incident > last_fetch:
            last_fetch = created_incident


    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': last_fetch}
    return next_run, incidentsList

''' HELPERS '''
def get_client(params):
    authorization = params.get('credentials').get(
        'identifier') + ":" + params.get('credentials').get('password')
    auth_byte = authorization.encode('utf-8')
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
    
    client = Client(
        base_url=base_url,
        verify=False,
        headers=headers,
        proxy=proxy)
    return client

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    params = demisto.params()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = get_client(params)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'cryptosim-get-correlations':
            return_results(correlations_command(client))

        elif demisto.command() == 'cryptosim-get-correlation-alerts':
            return_results(correlation_alerts_command(client))

        elif demisto.command() == 'fetch-incidents':

            next_run, incidents = fetch_incidents(client)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"""Failed to execute {demisto.command()}
command.\nError:\n{str(e)}""")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()