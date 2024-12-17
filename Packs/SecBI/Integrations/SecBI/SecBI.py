import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
SECBI_API_ROOT = '/api/v1'
SECBI_API_ENDPOINT_STATUS = SECBI_API_ROOT + '/status'
SECBI_API_ENDPOINT_INCIDENT = SECBI_API_ROOT + '/thirdparties/integration/incident'
SECBI_API_ENDPOINT_INCIDENTS = SECBI_API_ROOT + '/thirdparties/integration/incidents'
SECBI_INCIDENT_FIELDS = ['id', 'host', 'identity', 'internalIp', 'sIp', 'firstAppearance', 'lastAppearance']

''' HELPER FUNCTIONS '''


def capitalize(s: str):
    return s[0].upper() + s[1:]


def as_secbi_incident(incident_json: dict):
    secbi_incident = {capitalize(field): incident_json.get(field, []) for field in SECBI_INCIDENT_FIELDS}
    secbi_incident['ID'] = secbi_incident.pop('Id')
    return secbi_incident


''' COMMANDS + REQUESTS FUNCTIONS '''


class SecBIClient(BaseClient):

    def secbi_get_incidents_list(self, query, limit):
        """
        SecBI Get All Incident IDs
        :param query: The Query by which to filter the Incident IDs
        :param limit: Limit amount of IDs to return (-1) for all
        :return: SecBI Incident IDs List
        """
        params = assign_params(query=query, limit=limit)
        LOG(f'Performing SecBI get_incidents_list request to {self._base_url}/{SECBI_API_ENDPOINT_INCIDENTS} with '
            f'params={str(params)}')
        return self._http_request(method='GET',
                                  url_suffix=SECBI_API_ENDPOINT_INCIDENTS,
                                  params=params)

    def secbi_get_incident(self, incident_id):
        """
        Get a specific SecBI Incident by SecBI Incident ID
        :param incident_id: SecBI incident ID
        :return: A dictionary representation of the SecBI Incident requested
        """
        params = assign_params(fields=SECBI_INCIDENT_FIELDS)
        return self._http_request(method='GET',
                                  url_suffix=f'{SECBI_API_ENDPOINT_INCIDENT}/{incident_id}',
                                  params=params)

    def secbi_get_incident_by_host(self, host):
        """
        Get a specific SecBI Incident by Host
        :param host: The host by which to get a SecBI Incident
        :return:  A dictionary representation of the SecBI Incident found to contain the supplied host
        """
        params = assign_params(host=host, fields=SECBI_INCIDENT_FIELDS)
        return self._http_request(method='GET', url_suffix=SECBI_API_ENDPOINT_INCIDENT, params=params)

    def test_module(self):
        """
        Performs basic get request to test SecBI system
        """
        return self._http_request(method='GET', url_suffix=SECBI_API_ENDPOINT_STATUS)


def test_module_command(client: SecBIClient):
    """
    This is the call made when pressing the integration test button.
    Performs basic get request to test SecBI system
    :param client: The SecBI client to use for the sanity test
    """
    try:
        results = client.test_module()
        if 'status' in results and results['status'] == 'ACTIVE':
            demisto.results('ok')
    except DemistoException as e:
        raise DemistoException("Failed connection test of SecBI. Please check your SECBI_API_URL and SECBI_API_KEY", e.args[0])


def secbi_get_incidents_list_command(client: SecBIClient, args: dict) -> tuple[str, dict, dict]:
    """
    SecBI Get All Incident IDs command
    :param client: The SecBI client to use
    :param args: The Demisto args
    :return: Content for return_outputs()
    """
    query = args.get('query', None)
    limit = args.get('limit', 100)
    incidents_list = client.secbi_get_incidents_list(query, limit)

    formatted = [{'ID': s} for s in incidents_list]
    human_readable = tableToMarkdown('List of SecBI Incidents', formatted)
    entry_context = {
        'SecBI.IncidentsList': incidents_list
    }
    return human_readable, entry_context, incidents_list


def secbi_get_incident_command(client: SecBIClient, args: dict) -> tuple[str, dict, dict]:
    """
    SecBI Get Incident command
    :param client: The SecBI client to use
    :param args: The Demisto args
    :return: Content for return_outputs()
    """
    incident_id = args.get('incident_id', None)
    raw_incident = client.secbi_get_incident(incident_id)
    incident_data = as_secbi_incident(raw_incident)

    human_readable = tableToMarkdown(f'SecBI incident ID "{incident_id}"', incident_data)
    entry_context = {
        'SecBI.Incident(val.ID === obj.ID)': incident_data
    }
    return human_readable, entry_context, raw_incident


def secbi_get_incident_by_host_command(client: SecBIClient, args: dict) -> tuple[str, dict, dict]:
    """
    SecBI Get Incident by Host command
    :param client: The SecBI client to use
    :param args: The Demisto args
    :return: Content for return_outputs()
    """
    host = args.get('host', None)
    raw_incident = client.secbi_get_incident_by_host(host)
    incident_data = as_secbi_incident(raw_incident)

    human_readable = tableToMarkdown(f'SecBI incident by host "{host}"', incident_data)
    entry_context = {
        # ID comparison might be problematic if the host changes Incidents and the ID changes
        'SecBI.Incident(val.ID === obj.ID)': incident_data
    }
    return human_readable, entry_context, raw_incident


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    LOG(f'Command being called is {demisto.command()}')

    params = demisto.params()
    command = demisto.command()

    should_validate_cert = not params.get('insecure', False)
    proxy = params.get('proxy')

    api_url = params.get('API_URL')
    api_key = params.get('API_KEY')

    # Headers to be sent in requests
    headers = {
        'secbi_api_key': api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    ok_codes = (200, 204)

    client = SecBIClient(base_url=api_url,
                         verify=should_validate_cert,
                         proxy=proxy,
                         ok_codes=ok_codes,
                         headers=headers)
    # Switch case
    commands = {
        'secbi-get-incidents-list': secbi_get_incidents_list_command,
        'secbi-get-incident': secbi_get_incident_command,
        'secbi-get-incident-by-host': secbi_get_incident_by_host_command
    }

    try:
        if command == 'test-module':
            test_module_command(client)
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
    # Log exceptions
    except Exception as e:
        msg = getattr(e, 'message', repr(e))
        return_error(str(msg), error=e)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
