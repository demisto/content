from datetime import datetime, timedelta
from CommonServerPython import *
from CommonServerUserPython import *
import traceback
import json
import base64
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class Client(BaseClient):
    def correlation_alerts(self, last_fetch_time=None):
        args = demisto.args()

        end_time = datetime.utcnow() + timedelta(hours=int(demisto.params().get("time_zone_difference", 3)))
        interval_time = end_time - timedelta(minutes=int(demisto.params().get('incidentFetchInterval', 360)))

        formatted_start_time = datetime.strptime(last_fetch_time, DATE_FORMAT) + timedelta(
            hours=int(demisto.params().get("time_zone_difference", 3))) if last_fetch_time is not None else None

        if last_fetch_time is None or formatted_start_time < interval_time:  # type: ignore
            formatted_start_time = interval_time

        if formatted_start_time >= end_time:    # type: ignore
            formatted_start_time = formatted_start_time - timedelta(  # type: ignore
                minutes=int(demisto.params().get('incidentFetchInterval', 360)))

        parameters = {
            'startDate': args.get('startDate', formatted_start_time.isoformat()),  # type: ignore
            'endDate': args.get('endDate', end_time.isoformat()),
            'showSolved': args.get('showSolved', False),
            'crrPluginId': args.get('crrPluginId', -1),
            'containStr': args.get('containStr', None),
            'risk': args.get('risk', -1),
            'srcIPPort': args.get('srcIPPort', None),
            'destIPPort': args.get('destIPPort', None),
            'srcPort': args.get('srcPort', None),
            'destPort': args.get('destPort', None),
            'riskOperatorID': args.get('riskOperatorID', "equal"),
            "limit": int(args.get("limit", '100')),
            "isJsonLog": True
        }

        return self._http_request("POST", url_suffix="correlationalertswithlogs",
                                  data=json.dumps(parameters))

    def correlations(self):
        args = demisto.args()

        limit = str(args.get("limit", '100'))
        limit_url = "limit=" + limit

        sort_type = str(args.get("sortType", "asc"))
        sort_type_url = "sortType=" + sort_type

        base_url = "correlations?"
        api_url = base_url + limit_url + "&" + sort_type_url
        return self._http_request("GET", data={}, url_suffix=api_url)

    def connection_test(self):
        return self._http_request("GET", data={}, url_suffix="correlations?limit=1")


''' COMMAND FUNCTIONS '''


def correlation_alerts_command(client: Client):
    # Call the Client function and get the raw response
    result = client.correlation_alerts()
    readable_data = []
    for res in result["Data"]:
        res = res["CorrelationAlert"]
        readable_data.append(
            {"ID": res.get('ID', ""), "CORRELATIONID": res.get('CORRELATIONID', ""),
             "RULEID": res.get('RULEID', ""), "NAME": res.get('NAME', ""),
             "Severity": res.get('RISK', ""),
             "Created At": res.get('EVENTSTARTDATE', "")})
    markdown = tableToMarkdown('Messages', readable_data,
                               headers=['ID', 'CORRELATIONID', 'NAME', 'RULEID', 'Severity', 'Created At'])
    return CommandResults(
        outputs_prefix='CorrelationAlerts',
        outputs_key_field='',
        readable_output=markdown,
        outputs=result,
    )


def correlations_command(client: Client):
    result = client.correlations()

    readable_data = []
    for res in result["Data"]:
        readable_data.append(
            {"Correlation ID": res.get('CorrelationId', ""), "Correlation Name": res.get('Name', "")})
    markdown = tableToMarkdown('Messages', readable_data, headers=['Correlation ID', 'Correlation Name'])

    return CommandResults(
        outputs_prefix='Correlations',
        outputs_key_field='',
        readable_output=markdown,
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
        if client.connection_test().get('StatusCode') == 200:
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


def fetch_incidents(client: Client, params):
    max_results = arg_to_number(arg=params.get('max_fetch', 20), arg_name='max_fetch', required=False)

    first_fetch_time = arg_to_datetime(params.get('first_fetch'), "1 hour").strftime(DATE_FORMAT)  # type: ignore

    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch', first_fetch_time)

    incidentsList = []
    alert_response = client.correlation_alerts(last_fetch_time=last_fetch)
    incident_data = alert_response.get("Data", [])

    for i, inc in enumerate(incident_data):

        if i >= max_results:  # type: ignore
            break

        incident_name = demisto.get(inc, 'CorrelationAlert.NAME')
        time_stamp = demisto.get(inc, 'CorrelationAlert.CREATEDATE') + "Z"

        severity_level = int(demisto.get(inc, 'CorrelationAlert.RISK', -1))
        if severity_level >= 0 and severity_level <= 5:
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
        demisto.get(inc, 'Log').pop("log", None)

        incident_object = {**inc['Log'], **inc['CorrelationAlert']}

        incident = {
            'name': incident_name,
            'occurred': time_stamp,
            'rawJSON': json.dumps(incident_object),
            "severity": severity,
            'type': 'Crpyotsim Correlation Alerts'
        }

        incidentsList.append(incident)

        created_incident = datetime.strptime(time_stamp, DATE_FORMAT)
        last_fetch = datetime.strptime(last_fetch, DATE_FORMAT) if isinstance(last_fetch, str) else last_fetch
        if created_incident > last_fetch + timedelta(hours=int(demisto.params().get("time_zone_difference", 3))):
            last_fetch = created_incident + timedelta(milliseconds=10)

    last_fetch = last_fetch.strftime(DATE_FORMAT) if not isinstance(last_fetch, str) else last_fetch
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


def main() -> None:  # pragma: no cover
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

            next_run, incidents = fetch_incidents(client, params)
            demisto.error(json.dumps(next_run))
            demisto.error(json.dumps(incidents))
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"""Failed to execute {demisto.command()} command.\nError:\n{str(e)}""")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
