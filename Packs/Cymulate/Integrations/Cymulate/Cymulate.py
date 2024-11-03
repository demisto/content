from CommonServerPython import *

''' IMPORTS '''
import urllib3
import dateparser
from datetime import datetime, timedelta
import enum

# disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
BASE_URL = 'https://api.cymulate.com/v1/'
DEFAULT_LIMIT = 20

""" Helper functions """


def get_now():
    """ A wrapper function of datetime.now
    helps handle tests

    Returns:
        datetime: time right now
    """
    return datetime.now()


def ts_add_minutes(ts, minutes):
    return (datetime.strptime(ts, DATE_FORMAT) + timedelta(minutes=minutes)).strftime(DATE_FORMAT)


class CymulateModuleTypeEnum(enum.Enum):
    """
       Enum class of module types of cymulate attacks
    """

    APT = '1',
    IMMEDIATE_THREATS = '2',
    HOPPER = '3',
    PHISHING = '4',
    WAF = '5',
    DLP = '6',
    BROWSING = '7',
    EDR = '8',
    MITRE = '9',
    MAIL = '10'

    def __str__(self):
        return str(self.name)


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def general_api_query(self, route):
        """
        initiates a general cymulate api http request
        """
        data = self._http_request(
            method='GET',
            verify=False,
            url_suffix=route
        )

        return data.get('result')

    def test_api(self):
        """
        send a test call to api
        """

        results = self._http_request(
            method='GET',
            url_suffix='user/modules'
        )

        return results

    def get_attack_info(self, module_type, from_date):
        """ Get Threats Results ID's by Module Type.
        Args:
            module_type (CymulateModuleTypeEnum): module_type enum
            from_date (dateparser.time): the time which retrieve incidents greater than, if it's None - return all

        Returns:
            JSON - https results struct of { 'success' : true/false, 'data' : [{'Id' : '', 'Name' : '',
            'Timestamp : '', 'InProgress: ''}...] }
        """

        get_ids_route = ''

        if module_type == CymulateModuleTypeEnum.APT:
            get_ids_route = 'apt/ids'
        elif module_type == CymulateModuleTypeEnum.IMMEDIATE_THREATS:
            get_ids_route = 'immediate-threats/ids'
        elif module_type == CymulateModuleTypeEnum.HOPPER:
            get_ids_route = 'hopper/ids'
        elif module_type == CymulateModuleTypeEnum.PHISHING:
            get_ids_route = 'phishing/ids'
        elif module_type == CymulateModuleTypeEnum.WAF:
            get_ids_route = 'waf/ids'
        elif module_type == CymulateModuleTypeEnum.DLP:
            get_ids_route = 'dlp/ids'
        elif module_type == CymulateModuleTypeEnum.BROWSING:
            get_ids_route = 'browsing/ids'
        elif module_type == CymulateModuleTypeEnum.EDR:
            get_ids_route = 'edr/ids'
        elif module_type == CymulateModuleTypeEnum.MITRE:
            get_ids_route = 'mitre/ids'
        elif module_type == CymulateModuleTypeEnum.MAIL:
            get_ids_route = 'mail/ids'

        demisto.debug(f"url of get ids: {get_ids_route}?from={from_date}")

        results = self._http_request(
            method='GET',
            url_suffix=get_ids_route,
            params={'from': from_date}
        )

        return results['data']

    def get_attack_technical_info(self, module_type, incident_id):
        """ Get technical Data about incident.
        Args:
            module_type (CymulateModuleTypeEnum): module_type enum
            incident_id (string): The incident id

        Returns:
            JSON - https results struct of { 'success' : true/false, 'data' : [{'Id' : '', 'Name' : '',
            'Timestamp : '', 'InProgress: ''}...] }
        """

        technical_route = ''

        if module_type == CymulateModuleTypeEnum.APT:
            technical_route = 'apt/attack/technical'
        elif module_type == CymulateModuleTypeEnum.IMMEDIATE_THREATS:
            technical_route = 'immediate-threats/attack/technical'
        elif module_type == CymulateModuleTypeEnum.HOPPER:
            technical_route = 'hopper/attack/technical'
        elif module_type == CymulateModuleTypeEnum.PHISHING:
            technical_route = 'phishing/attack/technical'
        elif module_type == CymulateModuleTypeEnum.WAF:
            technical_route = 'waf/attack/technical'
        elif module_type == CymulateModuleTypeEnum.DLP:
            technical_route = 'dlp/attack/technical'
        elif module_type == CymulateModuleTypeEnum.BROWSING:
            technical_route = 'browsing/attack/technical'
        elif module_type == CymulateModuleTypeEnum.EDR:
            technical_route = 'edr/attack/technical'
        elif module_type == CymulateModuleTypeEnum.MITRE:
            technical_route = 'mitre/attack/technical'
        elif module_type == CymulateModuleTypeEnum.MAIL:
            technical_route = 'mail/attack/technical'

        results = self._http_request(
            method='GET',
            url_suffix=technical_route + "/" + incident_id,
        )

        return results['data']


def cymulate_test(client, is_fetch):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: cymulate client
        is_fetch (bool): indicate if test also 'fetch' function
    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    results = client.test_api()
    fetch_test = True

    # If 'is_fetch' selected - check also 'fetch_incidents'
    if is_fetch:
        next_run, incidents, remain_incidents = fetch_incidents(
            client=client,
            module_type=CymulateModuleTypeEnum.IMMEDIATE_THREATS,
            last_run={'last_fetch': '2020-12-02T16:32:37'},
            first_fetch_time={},
            only_penatrated=False,
            limit=20,
            integration_context=None)

        fetch_test = (next_run == {'last_fetch': '2020-12-02T16:32:37'})

    if results['success'] and fetch_test:
        return demisto.results('ok')
    else:
        return None


def fetch_incidents(client, module_type, last_run, first_fetch_time, only_penatrated,
                    limit=DEFAULT_LIMIT, integration_context=None):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): Cymulate client
        module_type (CymulateModuleTypeEnum): module_type enum
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time
        only_penatrated (boolean): Indicate if fetch only 'penatrated' incidents or all incidents
        limit: (integer): The limit of the incidents to retrieve
        integration_context: The integration's context that store on demisto side

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """

    # Check if there are remained incidents saved in context
    if integration_context:
        remained_incidents = integration_context.get("incidents")
        # return incidents if exists in context.
        if remained_incidents and len(remained_incidents) > 0:
            demisto.debug("there is remaines incidents and return them")
            return last_run, remained_incidents[:limit], remained_incidents[limit:]

    # Get the last fetch time, if exists
    start_query_time = last_run.get("last_fetch")

    # Handle first time fetch
    if not start_query_time:
        start_query_time, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)
        start_query_time = ts_add_minutes(start_query_time, 2)

    incidents = []
    # Get the incident from server
    items = client.get_attack_info(module_type, start_query_time)

    for item in items:
        if not item['InProgress']:
            technical_data = client.get_attack_technical_info(module_type, item['Id'])
            incident_created_time = dateparser.parse(item['Timestamp'])

            for incident in technical_data:
                # Manual add attack_id for mapping issue
                incident['Attack_ID'] = item['Id']

                if not only_penatrated or incident['Status'] == 'Penetrated':
                    assert incident_created_time is not None
                    incident_data = {
                        'name': item['Name'],
                        'occurred': incident_created_time.strftime(DATE_FORMAT),
                        'rawJSON': json.dumps(incident)
                    }

                    incidents.append(incident_data)

    if len(items) > 0 and len(incidents) > 0:
        demisto.debug("length of items is big than 0")
        last_incident_ts = incidents[len(incidents) - 1]['occurred']
        next_run_ts = (datetime.strptime(last_incident_ts, DATE_FORMAT) + timedelta(seconds=1)).strftime(DATE_FORMAT)
    else:
        demisto.debug("length of items is 0")
        next_run_ts = start_query_time

    next_run = {"last_fetch": next_run_ts}

    demisto.debug(f"start_query_time:{start_query_time}")
    demisto.debug(f"len(items):{len(items)}")
    demisto.debug(f"len(incidents):{len(incidents)}")
    demisto.debug(f"next_run:{next_run}")

    return next_run, incidents[:limit], incidents[limit:]


def cymulate_get_incident_info(client, attack_id):
    """
    This function return technical info about incident

    Args:
        client (Client): Cymulate client
        attack_id (String): The attack id

    Returns:
        Incident contained details technical data
    """

    # Get module_type
    module_type = CymulateModuleTypeEnum[demisto.args().get('module_type')]

    # Execute command on API
    technical_data = client.get_attack_technical_info(module_type, attack_id)

    return technical_data


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    session_token = demisto.params()['x-token']
    header = {"x-token": session_token}

    # How many time before the first fetch to retrieve incidents
    fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    # Get the module type
    module_type = demisto.params().get('module_type', CymulateModuleTypeEnum.IMMEDIATE_THREATS)

    # Fetch only 'penatrated'
    only_penatrated = demisto.params().get('onlyPenatrated', True)

    # Flag if use server proxy
    use_proxy = demisto.params().get('useProxy', False)

    # Flag if use server 'verification'
    insecure = demisto.params().get('insecure', False)

    # Flag if 'is_fetch'
    is_fetch = demisto.params().get('isFetch', False)

    # Amount limit of returned incidents
    fetch_limit = 25

    LOG(f'Command being called is: {demisto.command()}')
    demisto.debug(f"MAIN CALL , PARAMS session_token:{session_token} module_type:{module_type} only_penatrated:{only_penatrated} use_proxy:{use_proxy} insecure:{insecure}"
                  f" is_fetch:{is_fetch}")

    try:
        client = Client(
            base_url=BASE_URL,
            headers=header,
            verify=insecure,
            proxy=use_proxy)

        if demisto.command() == 'test-module':
            demisto.debug("******###CYMULATE-LOGS-START-TEST_MODULE!!!*******")

            # This is the call made when pressing the integration Test button.
            cymulate_test(client=client, is_fetch=is_fetch)

            demisto.debug("******###CYMULATE-LOGS-END-TEST_MODULE!!!*******")

        elif demisto.command() == 'fetch-incidents':
            demisto.debug("******###CYMULATE-LOGS-START-FETCH_INCIDENTS!!!*******")

            # Get the context
            integration_context = demisto.getIntegrationContext()
            demisto.debug(f"initial integration_context:{integration_context}")
            demisto.debug(f"initial last_run:{demisto.getLastRun()}")

            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents, remained_incidents = fetch_incidents(
                client=client,
                module_type=module_type,
                last_run=demisto.getLastRun(),
                first_fetch_time=fetch_time,
                only_penatrated=only_penatrated,
                limit=fetch_limit,
                integration_context=integration_context)

            demisto.debug(f"updated next_run:{next_run}")
            demisto.debug(f"return incidents:{incidents}")
            demisto.debug(f"return remained_incidents:{remained_incidents}")

            # Store next_run, incidents, remained incidents into integration
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

            # Store integration context
            integration_context['incidents'] = remained_incidents
            demisto.setIntegrationContext(integration_context)
            demisto.debug(f"updated integration_context:{integration_context}")

            demisto.debug("******###CYMULATE-LOGS-END-FETCH_INCIDENTS!!!*******")

        elif demisto.command() == 'cymulate-get-incident-info':
            demisto.debug("******###CYMULATE-LOGS-START-GET_INCIDENT_INFO!!!*******")

            # Get incident's parent id
            attack_id = demisto.args().get('attack_id')

            # Get incident_id
            incident_id = demisto.args().get('incident_id', None)

            demisto.debug(f"PARAMS attack_id:{attack_id} incident_id:{incident_id}")

            # Get technical data from server
            technical_data = cymulate_get_incident_info(
                client=client,
                attack_id=attack_id
            )

            demisto.debug(f"API RESULT technical_data_length:{len(technical_data)} technical_data:{technical_data}")

            if technical_data and len(technical_data) > 0:

                parsed_technical_data = []

                for incident in technical_data:
                    if incident_id is None or incident_id == incident['ID']:
                        parsed_technical_data.append({
                            'ID': incident['ID'],
                            'Attack_ID': attack_id,
                            'Name': incident['Name'],
                            'Status': incident['Status'],
                            'Attack_Type': incident['Attack_Type'],
                            'Attack_Vector': incident['Attack_Vector'],
                            'Timestamp': incident['Timestamp'],
                            'Attack_Payload': incident['Attack_Payload'],
                            'Md5': incident['Md5'],
                            'Mitigation': incident['Mitigation'],
                            'Module': incident['Module'],
                            'Penetration_Vector': incident['Penetration_Vector'],
                            'Sha1': incident['Sha1'],
                            'Sha256': incident['Sha256']
                        })

                # Convert to human reading format
                cymulate_output = tableToMarkdown('Cymulate Results', parsed_technical_data, ['ID', 'Attack_ID',
                                                                                              'Name',
                                                                                              'Status', 'Attack_Type',
                                                                                              'Attack_Vector',
                                                                                              'Timestamp',
                                                                                              'Attack_Payload',
                                                                                              'Md5',
                                                                                              'Mitigation',
                                                                                              'Module',
                                                                                              'Penetration_Vector',
                                                                                              'Sha1',
                                                                                              'Sha256'])
                outputs = {
                    "Cymulate.Incident(val.ID == obj.ID)": parsed_technical_data
                }

                demisto.debug(f"outputs results: {outputs}")

                # Return output to client
                return_outputs(
                    cymulate_output,
                    outputs,
                    technical_data  # raw response - the original response
                )
            else:
                # No Results format
                demisto.debug("NO Results")
                demisto.results('No results found.')

        demisto.debug("******###CYMULATE-LOGS-END-GET_INCIDENT_INFO!!!*******")

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
