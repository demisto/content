from datetime import datetime, timedelta
import demistomock as demisto
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
        if '401' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API User and Password is correctly set'
        else:
            raise e
    return message


''' INCIDENT '''


def fetch_incidents():
    max_results = arg_to_number(arg=demisto.params().get('max_fetch'), arg_name='max_fetch', required=False)


    first_fetch_time = arg_to_datetime(demisto.params.get('first_fetch')).isoformat()

    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch', first_fetch_time)


    severity = "high"

    incidentsList=[]
    incidentsResult = [{"NAME":"A", "AA":"1"},{"NAME":"C", "AA":"2"}]
    incidentsResult = client.correlation_alerts()

    for inc in incidentsResult:
        '''
        if last_fetch:
            if incident_created_time <= last_fetch:
                continue
        '''
        # If no name is present it will throw an exception
        incident_name = inc['NAME']

        incident = {
            'name': incident_name,
            'occurred': '2019-10-23T10:00:00Z',
            'rawJSON': json.dumps(inc),
            #'type': 'Crpyotsim CorrelationAlert',
            'severity': severity,
        }

        incidentsList.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        #if incident_created_time > latest_created_time:
        #    latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': last_fetch}
    return next_run, incidentsList


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
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
            return_results(correlation_alerts_command(client))

        elif demisto.command() == 'fetch-incidents':

            next_run, incidents = fetch_incidents()

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
