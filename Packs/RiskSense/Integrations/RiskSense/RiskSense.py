from CommonServerPython import *

''' IMPORTS '''
from typing import List, Dict, Any
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
RISKSENSE_FIELD_MAPPINGS = {
    'Total Findings': 'findingsDistribution.total',
    'Critical Findings': 'findingsDistribution.critical',
    'High Findings': 'findingsDistribution.high',
    'Medium Findings': 'findingsDistribution.medium',
    'Low Findings': 'findingsDistribution.low',
    'Info Findings': 'findingsDistribution.info',
    'Severity': 'severity',
    'Id': 'id',
    'ID': 'id',
    'Source': 'source',
    'Risk Rating': 'riskRating',
    'Network Name': 'network.name',
    'Address': 'url',
    'Name': 'name',
    'Network': 'network.name',
    'Title': 'titles',
    'IP Address': 'ipAddress',
    'Host Name': 'hostName',
    'Criticality': 'criticality',
    'RS3': 'rs3',
    'BETWEEN': 'RANGE',
    'ascending': 'ASC',
    'descending': 'DESC'
}
REGEX_FOR_YYYY_MM_DD = r'^[12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$'
REGEX_FOR_INR_OR_FLOAT = r'^\d+?(\.\d+)?$'
''' CLIENT CLASS'''


class Client(BaseClient):
    """
    Client to use in integration with powerful http_request.
    It extends the base client and uses the http_request method for the API request.
    Handle some exceptions externally.
    """

    def __init__(self, base_url, request_timeout, verify, proxy, headers):
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)  # type: ignore
        self.request_timeout = request_timeout

    def http_request(self, method, url_suffix, full_url=None, headers=None,
                     auth=None, json_data=None, params=None, data=None, files=None, resp_type='custom',
                     ok_codes=(200, 201, 400, 401, 404, 521, 403)):
        """
                Override http_request method from BaseClient class.
        :type method: ``str``
        :param method: The HTTP method, for example: GET, POST, and so on.

        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.

        :type full_url: ``str``
        :param full_url: Bypasses the use of self._base_url + url_suffix. This is useful if you need to
            make a request to an address outside of the scope of the integration API.

        :type headers: ``dict``
        :param headers: Headers to send in the request. If None, will use self._headers.

        :type auth: ``tuple``
        :param auth: The authorization tuple (usually username/password) to enable Basic/Digest/Custom HTTP Auth.
            if None, will use self._auth.

        :type params: ``dict``
        :param params: URL parameters to specify the query.

        :type data: ``dict``
        :param data: The data to send in a 'POST' request.

        :type json_data: ``dict``
        :param json_data: The dictionary to send in a 'POST' request.

        :type files: ``dict``
        :param files: The file data to send in a 'POST' request.

        :type resp_type: ``str``
        :param resp_type: Determines which data format to return from the HTTP request. The default
            is 'json'. Other options are 'text', 'content', 'xml' or 'response'. Use 'response'
            to return the full response object.

        :type ok_codes: ``tuple``
        :param ok_codes: The request codes to accept as OK, for example: (200, 201, 204). If you specify
                "None", will use self._ok_codes.

        :return: Depends on the resp_type parameter
        :rtype: ``dict`` or ``str`` or ``requests.Response``
        """

        resp = self._http_request(method, url_suffix, full_url, headers,
                                  auth, json_data, params, data, files,
                                  self.request_timeout, resp_type, ok_codes, proxies=handle_proxy())
        status_code = resp.status_code

        if status_code != 200:
            if status_code == 400:
                error_msg = str(resp.json().get('errors', ''))
                demisto.debug(
                    'RiskSense API call failed: Bad Request. One or more argument(s) are invalid. Error: {}'.format(
                        error_msg))
                raise ValueError('RiskSense API call failed: Bad Request. One or more argument(s) are invalid.')
            elif status_code == 401:
                raise ValueError('Unauthenticated. Check the API key configured.')
            elif status_code == 403:
                raise ValueError('Unauthorized. Check the permissions associated with API key configured.')
            elif status_code == 404:
                raise ValueError('No record(s) found.')
            # handling any server error
            elif status_code >= 500:
                raise ValueError('API call failed. Server error received.')
            else:
                resp.raise_for_status()

        return resp.json()


''' HELPER FUNCTIONS '''


def validate_arguments(args):
    """
    Validate argument of the commands

    :param args: command arguments
    :return: True if arguments are valid else return error
    :rtype: bool
    """

    size = args.get('size', "10")
    page = args.get('page', "0")
    sort_order = args.get('sort_direction', 'ascending').lower()
    exclusive_operator = args.get('exclude', 'False').lower()
    if sort_order not in ['ascending', 'descending']:
        raise ValueError('Sort_direction argument should be either Ascending or Descending.')

    if exclusive_operator not in ['true', 'false']:
        raise ValueError('Exclude argument should be either true or false.')

    if not str(size).isdigit() or int(size) == 0:
        raise ValueError('Size argument must be a non-zero positive number. Accepted values between 1-1000.')

    if not str(page).isdigit():
        raise ValueError('Page argument must be positive number.')
    if int(size) > 1000:
        raise ValueError('Maximum size supported by RiskSense is 1000.')
    return True


def get_client_detail_from_context(client):
    """
    Initializes a RiskSense context and set list of client id and client name in it.
    Client id is fetched from the Demisto's integration context if client name matches.
    if not, make an API call and updates integration context.

    This way we can eliminate the number of repeated API calls by retrieving client id using client name.

    :param client: client class object.
    :return: client detail ({id:, name:})
    """
    integration_context = demisto.getIntegrationContext()
    client_name = demisto.params().get('client_name')

    for client_detail in integration_context.get('RiskSenseContext', []):
        if client_name == client_detail['ClientName']:
            return client_detail

    # list client API call
    resp_json = client.http_request('GET', url_suffix='')

    client_id = None
    for client in resp_json.get('_embedded', {}).get('clients', []):
        if client['name'] == client_name:
            client_id = client['id']

    # prepare integration context
    client_details = integration_context.get('RiskSenseContext', [])
    client_detail = {
        'ClientName': client_name,
        'Id': client_id
    }
    client_details.append(client_detail)
    demisto.setIntegrationContext({'RiskSenseContext': client_details})

    return client_detail


def prepare_filter_payload(args, projection=None):
    """
    Prepare body (raw-json) for post API request.
    Used in 'risksense-get-hosts', 'risksense-get-host-findings', 'risksense-get-apps' and
    'risksense-get-unique-open-findings' commands.

    :param args: Demisto argument provided by user
    :param projection: projection is used to get detail response or basic response from RiskSense.
    :return: data in json format
    :rtype ``dict``
    :raises ValueError exception if required params are missing
    """
    # Fetching value of arguments.
    fieldname = args.get('fieldname', '')
    operator = args.get('operator', '')
    exclusive_operator = args.get('exclude', '').lower()
    value = args.get('value', '')
    page = args.get('page')  # defaultValue 0
    size = args['size']  # defaultValue 10
    sort_by = args['sort_by']
    sort_order = args['sort_direction'].lower()  # defaultValue asc
    data = {}  # type: Dict[str, Any]
    filters = []  # type: List[Dict[str, Any]]
    sort_detail = []  # type: List[Dict[str, Any]]

    # If either of fieldname, value, operator or exculsive_operator are provided
    # then validate their required fields
    if fieldname or value or operator or exclusive_operator:
        if not fieldname:
            raise ValueError('fieldname is missing.')
        if not value:
            raise ValueError('value is missing.')
        if not operator:
            operator = 'EXACT'
        if not exclusive_operator:
            exclusive_operator = 'false'

        if operator in RISKSENSE_FIELD_MAPPINGS:
            operator = RISKSENSE_FIELD_MAPPINGS[operator]

        if fieldname in RISKSENSE_FIELD_MAPPINGS:
            fieldname = RISKSENSE_FIELD_MAPPINGS[fieldname]

        # Check validation of IP Address in case of operator = EXACT
        if fieldname == 'ipAddress' and operator == 'EXACT':
            if not is_ip_valid(value, True):
                raise ValueError('IP Address is invalid.')

        # Check validation of multiple values
        validate_values_for_between_operator(args)

        filters.append(
            {
                'field': fieldname,
                'exclusive': exclusive_operator,
                'operator': operator,
                'value': value.lower()
            }
        )
        data['filters'] = filters

    # Adding sorting parameter in request API
    if sort_by and sort_order:
        if sort_by in RISKSENSE_FIELD_MAPPINGS:
            sort_by = RISKSENSE_FIELD_MAPPINGS[sort_by]
        sort_detail = [{'field': sort_by, 'direction': RISKSENSE_FIELD_MAPPINGS[sort_order]}]

    data['projection'] = projection
    data['sort'] = sort_detail
    data['page'] = page
    data['size'] = size

    return data


def add_filter_to_request(data, additional_fieldname, exclusive_operator, operator, value):
    """
    Adding additional filter to API-request.

    :param data: prepared request
    :param additional_fieldname: fieldname is used to create an additional filter.
    :param exclusive_operator: exclusive_operator is used to create an additional filter.
    :param operator: operator is used to create additional filter.
    :param value: value is used to create additional filter.
    :return: dict
    """
    filters = data.get('filters', [])
    filtr = {'field': additional_fieldname, 'exclusive': exclusive_operator,
             'operator': operator, 'value': value}
    filters.append(filtr)
    data['filters'] = filters

    return data


def get_host_context(resp_host):
    """
    Prepare host context data as per Demisto's standard.

    :param resp_host: response from host command.
    :return: Dictionary representing the Demisto standard host context.
    """
    return {
        'ID': resp_host.get('id', ''),
        'Hostname': resp_host.get('hostName', ''),
        'IP': resp_host.get('ipAddress', ''),
        'OS': resp_host.get('operatingSystemScanner', {}).get('name', '')
    }


def get_host_hr(resp_host):
    """
    Prepares human readable json for command 'risksense-get-hosts' command.

    :param resp_host: response from host command.
    :return: None
    """
    owner = [owner.get('value', '') for owner in resp_host.get('configurationManagementDB', []) if
             owner.get('key', '') == 'owned_by']
    return {
        'ID': resp_host.get('id', ''),
        'RS3': resp_host.get('rs3', ''),
        'xRS3': resp_host.get('xRS3', ''),
        'Host Name': resp_host.get('hostName', ''),
        'Criticality': resp_host.get('criticality', ''),
        'IP Address': resp_host.get('ipAddress', ''),
        'Network': resp_host.get('network', {}).get('name', ''),
        'Group': len(resp_host.get('groups', [])),
        'Total Findings': resp_host.get('findingsDistribution', {}).get('total', {}).get('value', 0),
        'Critical Findings': resp_host.get('findingsDistribution', {}).get('critical', {}).get('value', 0),
        'High Findings': resp_host.get('findingsDistribution', {}).get('high', {}).get('value', 0),
        'Medium Findings': resp_host.get('findingsDistribution', {}).get('medium', {}).get('value', 0),
        'Low Findings': resp_host.get('findingsDistribution', {}).get('low', {}).get('value', 0),
        'Info Findings': resp_host.get('findingsDistribution', {}).get('info', {}).get('value', 0),
        'OS': resp_host.get('operatingSystemScanner', {}).get('name', ''),
        'Tags': len(resp_host.get('tags', [])),
        'Notes': len(resp_host.get('notes', [])),
        'Owner': owner[0] if len(owner) == 1 else ','.join(owner),
        'External': resp_host.get('external', '')
    }


def get_services(services):
    """
    Get all services from the response and make the comma-separated string.

    :param services: List of services.
    :return: comma-separated list.
    """
    return ', '.join(services)


def get_risksense_host_context(href, resp_host):
    """
    Prepare context data under RiskSense host.

    :param href:  Reference link from host resp.
    :param resp_host: Response from host command.
    :return: None
    """
    return {
        'ID': resp_host.get('id', ''),
        'ClientID': resp_host.get('clientId', ''),
        'GroupID': resp_host.get('group', {}).get('id', ''),
        'GroupName': resp_host.get('group', {}).get('name', ''),

        # Prepare Group details
        'Group': get_group_detail(resp_host.get('groups', [])),
        'Rs3': resp_host.get('rs3', ''),
        'Xrs3': resp_host.get('xRS3', ''),
        'Criticality': resp_host.get('criticality', ''),

        # Prepare Tag details
        'Tag': get_tag_details(resp_host.get('tags', [])),

        'NetworkID': resp_host.get('network', {}).get('id', ''),
        'NetworkName': resp_host.get('network', {}).get('name', ''),
        'NetworkType': resp_host.get('network', {}).get('type', ''),
        'DiscoveredOn': resp_host.get('discoveredOn', ''),
        'LastFoundOn': resp_host.get('lastFoundOn', ''),
        'LastScanTime': resp_host.get('lastScanTime', ''),
        'HostName': resp_host.get('hostName', ''),
        'IpAddress': resp_host.get('ipAddress', ''),

        # Prepare port numbers in comma separated format
        'PortNumbers': get_port_numbers(resp_host.get('ports', [])),

        'OS': {
            'Name': resp_host.get('operatingSystemScanner', {}).get('name', ''),
            'Family': resp_host.get('operatingSystemScanner', {}).get('family', ''),
            'Class': resp_host.get('operatingSystemScanner', {}).get('class', ''),
            'Vendor': resp_host.get('operatingSystemScanner', {}).get('vendor', '')
        },

        'CMDB': get_cmdb_detail(resp_host.get('configurationManagementDB', [])),
        'Services': get_services(resp_host.get('services', [])),
        'Note': get_note_detail(resp_host.get('notes', [])),
        'Source': get_source_detail(resp_host.get('sources', [])),
        'Ticket': get_ticket_detail(resp_host.get('tickets', [])),

        'LastVulnTrendingOn': resp_host.get('lastVulnTrendingOn', ''),
        'LastThreatTrendingOn': resp_host.get('lastThreatTrendingOn', ''),
        'OldestOpenFindingWithThreatDiscoveredOn': resp_host.get('oldestOpenFindingWithThreatDiscoveredOn', ''),
        'Xrs3date': resp_host.get('xRS3date', ''),
        'DiscoveredByRS': resp_host.get('discoveredByRS', False),
        'Href': href,
        'Total': resp_host.get('findingsDistribution', {}).get('total', {}).get('value', 0),
        'Critical': resp_host.get('findingsDistribution', {}).get('critical', {}).get('value', 0),
        'High': resp_host.get('findingsDistribution', {}).get('high', {}).get('value', 0),
        'Medium': resp_host.get('findingsDistribution', {}).get('medium', {}).get('value', 0),
        'Low': resp_host.get('findingsDistribution', {}).get('low', {}).get('value', 0),
        'Info': resp_host.get('findingsDistribution', {}).get('info', {}).get('value', 0)
    }


def get_tag_details(tags):
    """
    Iterate over tag detail from response.

    :param tags: Tags detail from the response.
    :return: List of tag elements that include required field from tag details.
    """
    return [{
        'ID': tag.get('id', ''),
        'Name': tag.get('name', ''),
        'Category': tag.get('category', ''),
        'Description': tag.get('description', ''),
        'Created': tag.get('created', ''),
        'Updated': tag.get('updated', ''),
        'Color': tag.get('color', '')
    } for tag in tags]


def get_port_numbers(ports):
    """
    Get all port number from response and make comma-separated string

    :param ports: Port portion from response.
    :return: Comma-separated port numbers.
    """
    return ', '.join([str(port['number']) for port in ports])


def get_cmdb_detail(cmdb_details):
    """
    Iterate over CMDB details from response and convert them into RiskSense context.

    :param cmdb_details: CMDB details from response
    :return: List of CMDB elements which includes required fields from resp.
    """
    return [{
        'Order': cmdb_detail.get('order', ''),
        'Key': cmdb_detail.get('key', ''),
        'Value': cmdb_detail.get('value', ''),
        'Label': cmdb_detail.get('label', '')
    } for cmdb_detail in cmdb_details]


def get_note_detail(notes):
    """
    Iterate over note details from response and prepare RiskSense context.

    :param notes: note details from the response.
    :return: List of note elements that include required fields from resp.
    """
    return [{
        'UserID': note.get('user', {}).get('id', ''),
        'UserName': note.get('user', {}).get('name', ''),
        'Note': note.get('note', ''),
        'Date': note.get('date', '')
    } for note in notes]


def get_source_detail(sources):
    """
    Iterate over source details from response and prepare RiskSense context.

    :param sources: source details from response.
    :return: List of source details which includes required fields from resp.
    """
    return [{
        'Name': source.get('name', ''),
        'UuID': source.get('uuid', ''),
        'ScannerType': source.get('scannerType', '')
    } for source in sources]


def get_ticket_detail(tickets):
    """
    Iterate over ticket details from response.

    :param tickets: ticket details from the response.
    :return: List of ticket details which include required fields from resp.
    """
    return [{
        'TicketNumber': ticket.get('ticketNumber', ''),
        'TicketStatus': ticket.get('ticketStatus', ''),
        'DeepLink': ticket.get('deepLink', ''),
        'Type': ticket.get('type', ''),
        'ConnectorName': ticket.get('connectorName', ''),
        'DetailedStatus': ticket.get('detailedStatus', '')
    } for ticket in tickets]


def prepare_payload_for_detail_commands(args):
    """
    Prepares body (raw-json) for post API request.
    Use in 'risksense-get-host-detail", "risksense-get-app-detail" and "risksense-get-host-finding-detail" commands.

    :param args: Demisto argument provided by user
    :return: data in json format
    :rtype ``dict``

    :raises ValueError exception if args key are not defined.
    """
    field = ''
    value = ''
    argument = {
        'host': 'hostname',
        'host_id': 'id',
        'application_id': 'id',
        'hostfinding_id': 'id'
    }
    for key, val in argument.items():
        if key in args:
            value = args.get(key)
            field = val

    if not field:
        raise ValueError('Argument is mandatory.')

    # Check validation of multiple values
    if len(value.split(',')) > 1:
        raise ValueError('Multiple values are not supported by command.')

    filter_dict = {'field': field, 'exclusive': False, 'operator': 'EXACT', 'value': value}
    return {'filters': [filter_dict], 'projection': 'detail'}


def get_findings_distribution_hr(findings_dict):
    """
    Prepare findings distribution for human readable in 'risksense-get-host-detail' and
    'risksense-get-app-detail' commands.

    :param findings_dict: Dictionary of finding distributions.
    :return: List containing finding distribution dictionary.
    """
    return [{
        'Total': findings_dict.get('total', {}).get('value', 0),
        'Critical': findings_dict.get('critical', {}).get('value', 0),
        'High': findings_dict.get('high', {}).get('value', 0),
        'Medium': findings_dict.get('medium', {}).get('value', 0),
        'Low': findings_dict.get('low', {}).get('value', 0),
        'Info': findings_dict.get('info', {}).get('value', 0)
    }, {}]  # To present human readable horizontally


def get_host_details_hr(host_dict):
    """
    Prepare host detail dictionary for human readable in 'risksense-get-host-detail' command.

    :param host_dict: Dictionary containing host detail.
    :return: List containing host detail dictionary.
    """
    return [{
        'Name': host_dict.get('hostName', ''),
        'IP': host_dict.get('ipAddress', ''),
        'RS3': host_dict.get('rs3', ''),
        'Discovered On': host_dict.get('discoveredOn', ''),
        'Last Found On': host_dict.get('lastFoundOn', '')
    }, {}]  # To present human readable horizontally


def get_operating_system_hr(os_dict):
    """
    Prepare operating system detail for human readable in 'risksense-get-host-detail' command.

    :param os_dict: Dictionary containing operating system detail.
    :return: List containing operating system detail dictionary.
    """
    return [{
        'Name': os_dict.get('name', ''),
        'Vendor': os_dict.get('vendor', ''),
        'Class': os_dict.get('class', ''),
        'Family': os_dict.get('family', '')
    }, {}]  # To present human readable horizontally


def get_tag_details_hr(tags):
    """
    Iterate over tags list for human readable in 'risksense-get-host-detail', 'risksense-get-app-detail' commands.
    if only one record found it will add blank dictionary to list to display horizontally in table.

    :param tags: Tags detail from the response.
    :return: List of tag elements that include required field from tag details.
    """
    tag_list = [{
        'ID': tag.get('id', ''),
        'Name': tag.get('name', ''),
        'Category': tag.get('category', ''),
        'Description': tag.get('description', ''),
        'Created': tag.get('created', ''),
        'Updated': tag.get('updated', '')
    } for tag in tags]

    # To present human readable horizontally
    if len(tags) == 1:
        tag_list.append({})

    return tag_list


def get_source_detail_hr(sources):
    """
    Iterate over source details from response.
    make comma-separated string from sources.

    :param sources: source details from response.
    :return: String of multiple source names.
    """
    return ', '.join([source.get('name', '') for source in sources])


def get_ticket_detail_hr(tickets):
    """
    Iterate over tickets list for human readable in 'risksense-get-host-detail' and 'risksense-get-app-detail' commands.
    if only one record found it will add blank dictionary to list to display horizontally in table.

    :param tickets: ticket details from the response.
    :return: List of ticket details which include required fields from resp.
    """
    ticket_list = [{
        'Ticket Number': ticket.get('ticketNumber', ''),
        'Ticket Status': ticket.get('ticketStatus', ''),
        'Deep Link': ticket.get('deepLink', ''),
        'Type': ticket.get('type', ''),
        'Connector Name': ticket.get('connectorName', ''),
        'Detailed Status': ticket.get('detailedStatus', '')
    } for ticket in tickets]

    # To present human readable horizontally
    if len(tickets) == 1:
        ticket_list.append({})

    return ticket_list


def get_host_detail_hr(host_detail_dict):
    """
    Prepare human readable string for the 'risksense-get-host-detail' command.

    :param host_detail_dict: Dictionary of host detail.
    :return: String represent human readable output.
    """
    hr = '### Group Details: '
    if host_detail_dict.get('group', {}).get('name', ''):
        hr += '\n Name: ' + host_detail_dict.get('group', {}).get('name', '')
    else:
        hr += '\n No data.'

    hr += '\n ### Sources:'
    if host_detail_dict.get('sources', []):
        hr += '\n Scanner(s): ' + get_source_detail_hr(host_detail_dict.get('sources'))
    else:
        hr += '\n No data.'

    hr += '\n ### Most Recently Identified Service(s): '

    if host_detail_dict.get('services', []):
        hr += '\n' + get_services(host_detail_dict.get('services')) + '\n'
    else:
        hr += '\n No data.\n'

    hr += tableToMarkdown('Host Details:', get_host_details_hr(host_detail_dict),
                          ['Name', 'IP', 'RS3', 'Discovered On', 'Last Found On'], removeNull=True)
    findings_distribution = get_findings_distribution_hr(host_detail_dict.get('findingsDistribution', {}))
    hr += '\n' + tableToMarkdown('Findings Distribution:', findings_distribution,
                                 ['Total', 'Critical', 'High', 'Medium', 'Low', 'Info'], removeNull=True)

    hr += tableToMarkdown('Operating System: ',
                          get_operating_system_hr(host_detail_dict.get('operatingSystemScanner', {})),
                          ['Name', 'Vendor', 'Class', 'Family'], removeNull=True)

    hr += tableToMarkdown('Tag(s) (' + str(len(host_detail_dict.get('tags', []))) + '):',
                          get_tag_details_hr(host_detail_dict.get('tags', [])),
                          ['Name', 'Category', 'Description', 'Created', 'Updated'], removeNull=True)
    hr += tableToMarkdown('Ticket(s) (' + str(len(host_detail_dict.get('tickets', []))) + '):',
                          get_ticket_detail_hr(host_detail_dict.get('tickets', [])),
                          ['Ticket Number', 'Ticket Status', 'Deep Link', 'Type', 'Connector Name'], removeNull=True)

    return hr


def prepare_unique_cves_payload(args):
    """
    Prepare body (raw-json) for post API request. Used in "risksense-get-unique-cves" command.

    :param args: Demisto argument provided by user
    :return: data in json format
    :rtype ``dict``
    """
    request_data = {}  # type: Dict[str, Any]
    value = args.get('hostFindingId')

    # Check validation of multiple value
    if len(value.split(',')) > 1:
        raise ValueError('Multiple values are not supported by this command.')

    request_data['filters'] = [{'field': 'id', 'operator': 'EXACT', 'value': value}]
    request_data['projection'] = 'detail'
    request_data['page'] = 0
    request_data['size'] = 10
    return request_data


def get_vulnerabilities_hr(vulnerability_list):
    """
    Extract attributes for human readable from each vulnerabilities. Used in the 'risksense-get-unique-cves' command.

    :param vulnerability_list: List of vulnerabilities.
    :return: List represent vulnerabilities detail in human readable form.
    """
    return [{'Name': vuln_info_dict.get('cve', ''),
             'V2/Score': vuln_info_dict.get('baseScore', ''),
             'Attack Vector': vuln_info_dict.get('attackVector', ''),
             'Attack Complexity': vuln_info_dict.get('accessComplexity', ''),
             'Authentication': vuln_info_dict.get('authentication', ''),
             'Confidentiality Impact': vuln_info_dict.get('confidentialityImpact', ''),
             'Integrity Impact': vuln_info_dict.get('integrity', ''),
             'Availability Impact': vuln_info_dict.get('availabilityImpact', ''),
             'Summary': vuln_info_dict['summary']
             } for vuln_info_dict in vulnerability_list]


def get_unique_cves_context(unique_cves_list, host_finding_id):
    """
    Iterate over vulnerability list and extract attribute for context data.
    This method is used in 'risksense-get-unique-cves' command.

    :param unique_cves_list: List of vulnerabilities.
    :param host_finding_id: The unique host finding ID
    :return: None.
    """
    return [{
        'HostFindingID': host_finding_id,
        'Cve': unique_cves_dict.get('cve', ''),
        'BaseScore': unique_cves_dict.get('baseScore', ''),
        'ThreatCount': unique_cves_dict.get('threatCount', ''),
        'AttackVector': unique_cves_dict.get('attackVector', ''),
        'AccessComplexity': unique_cves_dict.get('accessComplexity', ''),
        'Authentication': unique_cves_dict.get('authentication', ''),
        'ConfidentialityImpact': unique_cves_dict.get('confidentialityImpact', ''),
        'Integrity': unique_cves_dict.get('integrity', ''),
        'AvailabilityImpact': unique_cves_dict.get('availabilityImpact', ''),
        'Trending': unique_cves_dict.get('trending', ''),
        'VulnLastTrendingOn': unique_cves_dict.get('vulnLastTrendingOn', '')
    } for unique_cves_dict in unique_cves_list]


def get_unique_open_finding_context(unique_open_findings_dict, href):
    """
    Prepare open findings dictionary for context data.
    This method is used in 'risksense-get-unique-open-findings' command.

    :param unique_open_findings_dict: Dictionary representing open host findings.
    :param href: hyperlink for page.
    :return: None.
    """
    return {
        'Title': unique_open_findings_dict.get('title', ''),
        'Severity': unique_open_findings_dict.get('severity', ''),
        'HostCount': unique_open_findings_dict.get('hostCount', ''),
        'Source': unique_open_findings_dict.get('source', ''),
        'SourceID': unique_open_findings_dict.get('sourceId', ''),
        'Href': href
    }


def get_unique_open_finding_hr(unique_open_finding):
    """
    Prepare open findings dictionary for human readable data.
    This method is used in 'risksense-get-unique-open-findings' command.

    :param unique_open_finding: Dictionary representing open host findings.
    :return: None.
    """
    return {
        'Title': unique_open_finding.get('title', ''),
        'Severity': unique_open_finding.get('severity', ''),
        'Asset Count': unique_open_finding.get('hostCount', ''),
        'Source': unique_open_finding.get('source', ''),
        'Source ID': unique_open_finding.get('sourceId', '')
    }


def get_group_detail(groups):
    """
    Iterate over group details from the response and retrieve details of groups.

    :param groups: list of group details from response
    :return: list of detailed element of groups
    :rtype: list
    """
    return [{
        'ID': group.get('id', ''),
        'Name': group.get('name', '')
    } for group in groups]


def get_port_detail(ports):
    """
    Iterate over ports details from response and retrieve details of ports.

    :param ports: list of ports details from response
    :return: list of detailed element of ports
    :rtype: list
    """
    return [{
        'ID': port.get('id', ''),
        'Number': port.get('number', '')
    } for port in ports]


def get_host_detail(host):
    """
    Retrieve host details from response.

    :param host: host details from response
    :return: host details
    :rtype: dict
    """
    return {
        'Criticality': host.get('criticality', ''),
        'External': host.get('external', ''),
        'Port': get_port_detail(host.get('ports', [])),
        'Rs3': host.get('rs3', '')
    }


def get_network_detail(network):
    """
    Retrieve network details from response.

    :param network: network details from response
    :return: network detail
    :rtype: dict
    """
    return {
        'ID': network.get('id', ''),
        'Name': network.get('name', ''),
        'Type': network.get('type', '')
    }


def get_assessment_detail(assessments):
    """
    Iterate over assessments details from response and retrieve details from assessments.

    :param assessments: list of assessments from response
    :return: list of detailed elements of assessments
    :rtype: list
    """
    return [{
        'ID': assessment.get('id', ''),
        'Name': assessment.get('name', ''),
        'Date': assessment.get('date', '')
    } for assessment in assessments]


def get_vulnerability_detail(vulnerabilities):
    """
    Iterate over vulnerabilities details from response and retrieve details related vulnerabilities.

    :param vulnerabilities: list of vulnerabilities from response
    :return: list of detailed elements of vulnerabilities
    :rtype: list
    """
    return [{
        'Cve': vulnerability.get('cve', ''),
        'BaseScore': vulnerability.get('baseScore', ''),
        'ThreatCount': vulnerability.get('threatCount', ''),
        'AttackVector': vulnerability.get('attackVector', ''),
        'AccessComplexity': vulnerability.get('accessComplexity', ''),
        'Authentication': vulnerability.get('authentication', ''),
        'ConfidentialityImpact': vulnerability.get('confidentialityImpact', ''),
        'Integrity': vulnerability.get('integrity', ''),
        'AvailabilityImpact': vulnerability.get('availabilityImpact', ''),
        'Trending': vulnerability.get('trending', ''),
        'VulnLastTrendingOn': vulnerability.get('vulnLastTrendingOn', ''),
        'Description': vulnerability.get('summary', '')
    } for vulnerability in vulnerabilities]


def get_threat_detail(threats):
    """
    Iterate over threat details from the response and retrieve details of threats.

    :param threats: list of threats from response
    :return: list of detailed elements of threats
    :rtype: list
    """
    return [{
        'Title': threat.get('title', ''),
        'Category': threat.get('category', ''),
        'Severity': threat.get('severity', ''),
        'Description': threat.get('description', ''),
        'Cve': threat.get('cves', []),
        'Source': threat.get('source', ''),
        'Published': threat.get('published', ''),
        'Updated': threat.get('updated', ''),
        'ThreatLastTrendingOn': threat.get('threatLastTrendingOn', ''),
        'Trending': threat.get('trending', '')
    } for threat in threats]


def get_patch_detail(patches):
    """
    Iterate over patch details from the response and retrieve details of the patch.

    :param patches: List of patch from response.
    :return: List of detailed elements of patch
    :rtype: list
    """
    return [{
        'Name': patch.get('name', ''),
        'Url': patch.get('url', '')
    } for patch in patches]


def get_tags_asset(tag_assets):
    """
    Iterate over tag assets list from response and retrieve details of tag assets

    :param tag_assets: List of tag assets from response
    :return: List of detailed elements of tag assets
    :rtype: list
    """
    return [{
        'ID': tag_asset.get('id', ''),
        'Name': tag_asset.get('name', ''),
        'Category': tag_asset.get('category', ''),
        'Created': tag_asset.get('created', ''),
        'Updated': tag_asset.get('updated', ''),
        'Color': tag_asset.get('color', ''),
        'Description': tag_asset.get('description', '')
    } for tag_asset in tag_assets]


def get_severity_detail(severity_detail):
    """
    Retrieve details of severity related fields.

    :param severity_detail: severity details from response
    :return: severity detail
    :rtype: dict
    """
    return {
        'Combined': severity_detail.get('combined', ''),
        'Overridden': severity_detail.get('overridden', ''),
        'Scanner': severity_detail.get('scanner', ''),
        'CvssV2': severity_detail.get('cvssV2', ''),
        'CvssV3': severity_detail.get('cvssV3', ''),
        'Aggregated': severity_detail.get('aggregated', ''),
        'State': severity_detail.get('state', ''),
        'StateName': severity_detail.get('stateName', ''),
        'ExpirationDate': severity_detail.get('expirationDate', '')
    }


def get_status_embeded_detail(status_embedded):
    """
    Retrieve details of status related fields.

    :param status_embedded: status details from response
    :return: status detail
    :rtype: dict
    """
    return {
        'State': status_embedded.get('state', ''),
        'StateName': status_embedded.get('stateName', ''),
        'StateDescription': status_embedded.get('stateDescription', ''),
        'Status': status_embedded.get('status', ''),
        'DurationInDays': status_embedded.get('durationInDays', ''),
        'DueDate': status_embedded.get('dueDate', ''),
        'ExpirationDate': status_embedded.get('expirationDate', '')
    }


def get_manual_finding_report_detail(manual_finding_reports):
    """
    Iterate over manual finding report detail from response.

    :param manual_finding_reports: manual finding report detail from the response
    :return: List of manual finding report elements.
    """
    return [{
        'ID': manual_finding_report.get('id', ''),
        'Title': manual_finding_report.get('title', ''),
        'Label': manual_finding_report.get('label', ''),
        'Pii': manual_finding_report.get('pii', ''),
        'Source': manual_finding_report.get('source', ''),
        'IsManualExploit': manual_finding_report.get('isManualExploit', ''),
        'EaseOfExploit': manual_finding_report.get('easeOfExploit', '')
    } for manual_finding_report in manual_finding_reports]


def get_assignment_detail(assignments):
    """
    Iterate over assignments detail from response.

    :param assignments: assignments detail from response.
    :return: list of assignment elements.
    """
    return [{
        'ID': assignment.get('id', ''),
        'FirstName': assignment.get('firstName', ''),
        'LastName': assignment.get('lastName', ''),
        'ReceiveEmails': assignment.get('receiveEmails', ''),
        'Email': assignment.get('email', ''),
        'Username': assignment.get('username', '')
    } for assignment in assignments]


def get_risksense_host_finding_context(resp_hostfinding):
    """
    Prepare context data for "risksense-get-host-findings" and "risksense-get-host-finding-detail" command.

    :param resp_hostfinding: host finding response
    :return: list of host finding context
    """
    return {
        'HostID': resp_hostfinding.get('host', {}).get('hostId', ''),
        'HostName': resp_hostfinding.get('host', {}).get('hostName', ''),
        'HostIpAddress': resp_hostfinding.get('host', {}).get('ipAddress', ''),
        'ID': resp_hostfinding.get('id', ''),
        'Source': resp_hostfinding.get('source', ''),
        'SourceID': resp_hostfinding.get('sourceId', ''),
        'Title': resp_hostfinding.get('title', ''),
        'Port': resp_hostfinding.get('port', ''),
        'GroupCount': len(resp_hostfinding.get('groups', [])),
        'Group': get_group_detail(resp_hostfinding.get('groups', [])),
        'Host': get_host_detail(resp_hostfinding.get('host', {})),
        'Network': get_network_detail(resp_hostfinding.get('network', {})),
        'Assessment': get_assessment_detail(resp_hostfinding.get('assessments', [])),
        'Vulnerability': get_vulnerability_detail(resp_hostfinding.get('vulnerabilities', {}).get('vulnInfoList', [])),
        'ThreatCount': len(resp_hostfinding.get('threats', {}).get('threats', [])),
        'Threat': get_threat_detail(resp_hostfinding.get('threats', {}).get('threats', [])),
        'Patch': get_patch_detail(resp_hostfinding.get('patches', [])),
        'TagCount': len(resp_hostfinding.get('tags', [])),
        'Tag': get_tag_details(resp_hostfinding.get('tags', [])),
        'TagAssetCount': len(resp_hostfinding.get('tagsAsset', [])),
        'TagAsset': get_tags_asset(resp_hostfinding.get('tagsAsset', [])),
        'Output': resp_hostfinding.get('output', ''),
        'Severity': resp_hostfinding.get('severity', ''),
        'SeverityDetail': get_severity_detail(resp_hostfinding.get('severityEmbedded', {})),
        'RiskRating': resp_hostfinding.get('riskRating', ''),
        'Xrs3Impact': resp_hostfinding.get('xrs3Impact', ''),
        'Xrs3ImpactOnCategory': resp_hostfinding.get('xrs3ImpactOnCategory', ''),
        'LastFoundOn': resp_hostfinding.get('lastFoundOn', ''),
        'DiscoveredOn': resp_hostfinding.get('discoveredOn', ''),
        'ResolvedOn': resp_hostfinding.get('resolvedOn', ''),
        'ScannerName': resp_hostfinding.get('scannerName', ''),
        'FindingType': resp_hostfinding.get('findingType', ''),
        'MachineID': resp_hostfinding.get('machineId', ''),
        'StatusEmbedded': get_status_embeded_detail(resp_hostfinding.get('statusEmbedded', {})),
        'ManualFindingReportCount': len(resp_hostfinding.get('manualFindingReports', [])),
        'ManualFindingReport': get_manual_finding_report_detail(resp_hostfinding.get('manualFindingReports', [])),
        'NoteCount': len(resp_hostfinding.get('notes', [])),
        'Note': get_note_detail(resp_hostfinding.get('notes', [])),
        'Assignment': get_assignment_detail(resp_hostfinding.get('assignments', [])),
        'Services': get_services(resp_hostfinding.get('services', [])),
        'Ticket': get_ticket_detail(resp_hostfinding.get('tickets', [])),
        'GroupID': resp_hostfinding.get('group', {}).get('id', ''),
        'GroupName': resp_hostfinding.get('group', {}).get('name', '')
    }


def get_assignee(assignments):
    """
    Retrieve information if assignments and convert comma-separated string of firstName.

    :param assignments: assignment details from response.
    :return: comma-separated string
    """
    return ', '.join([assignment['firstName'] for assignment in assignments])


def get_host_finding_hr(host_finding):
    """
    Prepare json data for human-readable for host finding commands.

    :param host_finding: host finding details from response.
    :return: dict
    """
    return {
        'ID': host_finding['id'],
        'Risk': host_finding.get('riskRating', ''),
        'Severity': host_finding.get('severity', ''),
        'Host Name': host_finding.get('host', {}).get('hostName', ''),
        'IP Address': host_finding.get('host', {}).get('ipAddress', ''),
        'Title': host_finding.get('title', ''),
        'Criticality': host_finding.get('host', {}).get('criticality', ''),
        'Groups': len(host_finding.get('groups', [])),
        'Port': host_finding.get('port', ''),
        'RS3': host_finding.get('host', {}).get('rs3', ''),
        'State': host_finding.get('statusEmbedded', {}).get('state', ''),
        'Assignments': get_assignee(host_finding.get('assignments', [])),
        'Manual Finding Report Count': len(host_finding.get('manualFindingReports', [])),
        'Threats': len(host_finding.get('threats', {}).get('threats', [])),
        'Tags': len(host_finding.get('tags', [])),
        'Asset Tags': len(host_finding.get('tagsAsset', [])),
        'Note': len(host_finding.get('notes', []))
    }


def get_icon_detail(icon_details):
    """
    Iterate over icon details from response.
    This method is used in "risksense-get-apps" command.

    :param icon_details: Icon details from response.
    :return: List of required icon detail dictionary.
    """
    return [{
        'Type': icon_detail.get('type', ''),
        'OverlayText': icon_detail.get('overlayText', '')
    } for icon_detail in icon_details]


def get_cmdb_detail_apps(cmdb_detail):
    """
    Iterate over CMDB details from response.
    This method is used in "risksense-get-apps" command.

    :param cmdb_detail: CMDB details from response
    :return: List of CMDB elements which includes required fields from resp.
    """
    return {
        'ManufacturedBy': cmdb_detail.get('manufacturedBy', ''),
        'Model': cmdb_detail.get('model', ''),
        'MacAddress': cmdb_detail.get('macAddress', ''),
        'Location': cmdb_detail.get('location', ''),
        'ManagedBy': cmdb_detail.get('managedBy', ''),
        'OwnedBy': cmdb_detail.get('ownedBy', ''),
        'SupportedBy': cmdb_detail.get('supportedBy', ''),
        'SupportGroup': cmdb_detail.get('supportGroup', ''),
        'SysID': cmdb_detail.get('sysId', ''),
        'OperatingSystem': cmdb_detail.get('operatingSystem', ''),
        'LastScanDate': cmdb_detail.get('lastScanDate', ''),
        'FerpaComplianceAsset': cmdb_detail.get('ferpaComplianceAsset', ''),
        'HipaaComplianceAsset': cmdb_detail.get('hipaaComplianceAsset', ''),
        'PciComplianceAsset': cmdb_detail.get('pciComplianceAsset', '')
    }


def get_apps_context(apps_context, app_detail, href):
    """
    Prepare context data for "risksense-get-apps" command.

    :param apps_context: List of host elements which is retrieved from response as context data.
    :param app_detail: response from apps command.
    :param href:  hyperlink for page.
    :return: None
    """
    apps_context_detail = {
        'ID': app_detail.get('id', ''),
        'GroupID': app_detail.get('group', {}).get('id', ''),
        'GroupName': app_detail.get('group', {}).get('name', ''),
        'Groups': get_group_detail(app_detail.get('groups', [])),
        'Network': get_network_detail(app_detail.get('network', {})),
        'ClientID': app_detail.get('clientId', ''),
        'HostID': app_detail.get('hostId', ''),
        'Uri': app_detail.get('uri', ''),
        'Name': app_detail.get('name', ''),
        'Description': app_detail.get('description', ''),
        'NoteCount': len(app_detail.get('notes', [])),
        'DiscoveredOn': app_detail.get('discoveredOn', ''),
        'LastFoundOn': app_detail.get('lastFoundOn', ''),
        'Total': app_detail.get('findingsDistribution', {}).get('total', {}).get('value', 0),
        'Critical': app_detail.get('findingsDistribution', {}).get('critical', {}).get('value', 0),
        'High': app_detail.get('findingsDistribution', {}).get('high', {}).get('value', 0),
        'Medium': app_detail.get('findingsDistribution', {}).get('medium', {}).get('value', 0),
        'Low': app_detail.get('findingsDistribution', {}).get('low', {}).get('value', 0),
        'Info': app_detail.get('findingsDistribution', {}).get('info', {}).get('value', 0),
        'Icon': get_icon_detail(app_detail.get('icons', [])),
        'TagCount': len(app_detail.get('tags', [])),
        'UrlCount': app_detail.get('urlCount', 0),
        'Href': href,
        'CMDB': get_cmdb_detail_apps(app_detail.get('configurationManagementDB', {})),
        'Ticket': get_ticket_detail(app_detail.get('tickets', [])),
        'Source': get_source_detail(app_detail.get('sources', [])),
        'Note': get_note_detail(app_detail.get('notes', [])),
        'Tag': get_tag_details(app_detail.get('tags', []))
    }
    apps_context.append(apps_context_detail)


def get_apps_hr(app_detail):
    """
    Prepare human readable json for command 'risksense-get-apps' command.

    :param app_detail: response from host command.
    :return: None
    """
    return {
        'ID': app_detail.get('id', ''),
        'Address': app_detail.get('uri', ''),
        'Name': app_detail.get('name', ''),
        'Network': app_detail.get('network', {}).get('name', ''),
        'Groups': len(app_detail.get('groups', [])),
        'URLs': app_detail.get('urlCount', 0),
        'Total Findings': app_detail.get('findingsDistribution', {}).get('total', {}).get('value', 0),
        'Critical Findings': app_detail.get('findingsDistribution', {}).get('critical', {}).get('value', 0),
        'High Findings': app_detail.get('findingsDistribution', {}).get('high', {}).get('value', 0),
        'Medium Findings': app_detail.get('findingsDistribution', {}).get('medium', {}).get('value', 0),
        'Low Findings': app_detail.get('findingsDistribution', {}).get('low', {}).get('value', 0),
        'Info Findings': app_detail.get('findingsDistribution', {}).get('info', {}).get('value', 0),
        'Tags': len(app_detail.get('tags', [])),
        'Notes': len(app_detail.get('notes', []))
    }


def get_host_finding_details_hr(host_finding_detail):
    """
    Prepare human readable json for "risksense-get-host-finding-detail" command.
    Including basic details of host finding.

    :param host_finding_detail: host finding details from response
    :return: List of dict
    """
    return [{
        'Title': host_finding_detail.get('title', ''),
        'Host Name': host_finding_detail.get('host', {}).get('hostName', ''),
        'Ip Address': host_finding_detail.get('host', {}).get('ipAddress', ''),
        'Source': host_finding_detail.get('source', ''),
        'Network': host_finding_detail.get('network', {}).get('name', ''),
        'Risk Rating': host_finding_detail.get('riskRating', '')
    }, {}]  # To present human readable horizontally


def get_host_finding_threat_hr(threats):
    """
    Prepare human readable json for "risksense-get-host-finding-detail" command.
    Including threats details.

    :param threats: threats details from response
    :return: list of dict
    """
    threats_list = [{
        'Title': threat.get('title', ''),
        'Category': threat.get('category', ''),
        'Source': threat.get('source', ''),
        'CVEs': ', '.join(threat.get('cves', '')),
        'Published': threat.get('published', ''),
        'Updated': threat.get('updated', '')
    } for threat in threats]

    # To present human readable horizontally
    if len(threats) == 1:
        threats_list.append({})

    return threats_list


def get_host_finding_vulnerabilities_hr(vulnerabilities):
    """
    Prepare human readable json for "risksense-get-host-finding-detail" command.
    Including vulnerabilities details.

    :param vulnerabilities: vulnerabilities details from response.
    :return: list of dict
    """
    vulnerabilities_list = [{
        'Name': vulnerability.get('cve', ''),
        'V2/Score': vulnerability.get('baseScore', ''),
        'Threat Count': vulnerability.get('threatCount', ''),
        'Attack Vector': vulnerability.get('attackVector', ''),
        'Access Complexity': vulnerability.get('accessComplexity', ''),
        'Authentication': vulnerability.get('authentication', '')
    } for vulnerability in vulnerabilities]

    # To present human readable horizontally
    if len(vulnerabilities) == 1:
        vulnerabilities_list.append({})

    return vulnerabilities_list


def get_host_finding_status_hr(status):
    """
    Prepare human readable json for "risksense-get-host-finding-detail" command.
    Including status details.

    :param status: status details from response.
    :return: list of dict
    """
    return [{
        'State': status.get('state', ''),
        'Current State': status.get('stateName', ''),
        'Description': status.get('stateDescription', ''),
        'Duration': str(status.get('durationInDays', 0)) + ' day(s)',
        'Due Date': status.get('dueDate', ''),
        'Resolved On': status.get('expirationDate', '')
    }, {}]  # To present human readable horizontally


def get_manual_finding_report_detail_hr(manual_finding_report):
    """
    Prepare human readable json for "risksense-get-host-finding-detail" command.
    including manual finding report details.

    :param manual_finding_report: manual finding report details from response.
    :return: list of dict
    """
    manual_finding_reports_list = get_manual_finding_report_detail(manual_finding_report)

    # To present human readable horizontally
    if len(manual_finding_reports_list) == 1:
        manual_finding_reports_list.append({})

    return manual_finding_reports_list


def get_assessment_detail_hr(assessment_details):
    """
    Prepare human readable json for "risksense-get-host-finding-detail" command.
    including assessment details.

    :param assessment_details: assessment details from response.
    :return: list of dict
    """
    assessment_detail_list = get_assessment_detail(assessment_details)

    # To present human readable horizontally
    if len(assessment_detail_list) == 1:
        assessment_detail_list.append({})

    return assessment_detail_list


def get_host_finding_detail_hr(host_finding_detail):
    """
    Prepare human readable json for "risksense-get-host-finding-detail" command.

    :param host_finding_detail: host finding details from response.
    :return: human readable string
    """
    hr = '### Group Details: ' + '\n'
    if host_finding_detail.get('group', {}).get('name', ''):
        hr += 'Name: ' + host_finding_detail['group']['name'] + '\n'
    else:
        hr += '\n No data.\n'
    hr += tableToMarkdown("Host Finding Details:", get_host_finding_details_hr(host_finding_detail),
                          ['Host Name', 'Ip Address', 'Network', 'Source', 'Risk Rating', 'Title'], removeNull=True)

    threats = host_finding_detail.get('threats', {}).get('threats', [])
    hr += '\n' + tableToMarkdown("Threat(s) (" + str(len(threats)) + '):',
                                 get_host_finding_threat_hr(threats),
                                 ['Title', 'Category', 'Source', 'CVEs', 'Published', 'Updated'], removeNull=True)
    vulnerabilities = host_finding_detail.get('vulnerabilities', {}).get('vulnInfoList', [])
    hr += '\n' + tableToMarkdown("Vulnerabilities (" + str(len(vulnerabilities)) + '):',
                                 get_host_finding_vulnerabilities_hr(vulnerabilities),
                                 ['Name', 'V2/Score', 'Threat Count', 'Attack Vector',
                                  'Access Complexity', 'Authentication'], removeNull=True)

    status_detail = host_finding_detail.get('statusEmbedded', {})
    hr += '\n' + tableToMarkdown("Status:", get_host_finding_status_hr(status_detail),
                                 ['State', 'Current State', 'Description', 'Duration', 'Due Date', 'Resolved On'],
                                 removeNull=True)

    tags = host_finding_detail.get('tags', [])
    hr += '\n' + tableToMarkdown("Tag(s) (" + str(len(tags)) + '):', get_tag_details_hr(tags),
                                 ["Name", "Category", "Created", "Updated"], removeNull=True)

    manual_report = host_finding_detail.get('manualFindingReports', [])
    hr += '\n' + tableToMarkdown('Manual Finding Report(s) (' + str(len(manual_report)) + '):',
                                 get_manual_finding_report_detail_hr(manual_report),
                                 ['Title', 'Label', 'Pil', 'Source'], removeNull=True)

    ticket_detail = host_finding_detail.get('tickets', [])
    hr += '\n' + tableToMarkdown("Ticket(s) (" + str(len(ticket_detail)) + '):', get_ticket_detail_hr(ticket_detail),
                                 ['Ticket Number', 'Ticket Status', 'Deep Link', 'Type', 'Connector Name',
                                  'Detailed Status'], removeNull=True)

    assessment_detail = host_finding_detail.get('assessments', [])
    hr += '\n' + tableToMarkdown("Assessment(s) (" + str(len(assessment_detail)) + '):',
                                 get_assessment_detail_hr(assessment_detail), ['Name', 'Date'], removeNull=True)

    host_finding_description = host_finding_detail.get('description', '')
    if host_finding_description:
        hr += '\n' + '### Host Finding Description:' + '\n' + host_finding_description

    return hr


def get_app_details_hr(app_dict):
    """
    Prepare application detail dictionary for human readable in 'risksense-get-app-detail' command.

    :param app_dict: Dictionary containing application detail.
    :return: List containing application detail dictionary.
    """
    return [{
        'Address': app_dict.get('uri', ''),
        'Name': app_dict.get('name', ''),
        'Network Name': app_dict.get('network', {}).get('name', ''),
        'Network Type': app_dict.get('network', {}).get('type', ''),
        'Discovered On': app_dict.get('discoveredOn', ''),
        'Last Found On': app_dict.get('lastFoundOn', '')
    }, {}]  # To present human readable horizontally


def get_app_detail_hr(app_detail_dict):
    """
    Prepare human readable data for 'risksense-get-app-detail' command.

    :param app_detail_dict: Dictionary of application detail.
    :return: String represent human readable output.
    """
    hr = '### Group Details: '
    if app_detail_dict.get('group', {}).get('name', ''):
        hr += '\n Name: ' + app_detail_dict.get('group', {}).get('name', '')
    else:
        hr += '\n No data.'

    hr += '\n ### Sources: '
    if app_detail_dict.get('sources', []):
        hr += '\n Scanner(s): ' + get_source_detail_hr(app_detail_dict.get('sources', [])) + '\n'
    else:
        hr += '\n No data.\n'

    hr += tableToMarkdown('Application Details:', get_app_details_hr(app_detail_dict),
                          ['Address', 'Name', 'Network Name', 'Network Type', 'Discovered On', 'Last Found On'],
                          removeNull=True)

    findings_distribution = get_findings_distribution_hr(app_detail_dict.get('findingsDistribution', {}))
    hr += '\n' + tableToMarkdown(
        'Findings Distribution:',
        findings_distribution,
        ['Total', 'Critical', 'High', 'Medium', 'Low', 'Info'], removeNull=True)

    hr += tableToMarkdown('Tag(s) (' + str(len(app_detail_dict.get('tags', []))) + '):',
                          get_tag_details_hr(app_detail_dict.get('tags', [])),
                          ['Name', 'Category', 'Description', 'Created', 'Updated'], removeNull=True)

    hr += tableToMarkdown('Ticket(s) (' + str(len(app_detail_dict.get('tickets', []))) + '):',
                          get_ticket_detail_hr(app_detail_dict.get('tickets', [])),
                          ['Ticket Number', 'Ticket Status', 'Deep Link', 'Type', 'Connector Name'], removeNull=True)

    app_description = app_detail_dict.get('description', '')
    if app_description:
        hr += '\n ### Application Description:' + '\n' + app_description

    return hr


def get_request_timeout():
    """
    Validate and return the request timeout parameter.
    The parameter must be a positive integer.
    Default value is set to 60 seconds for API request timeout.

    :params req_timeout: Request timeout value.
    :return: boolean
    """
    try:
        request_timeout = int(demisto.params().get('request_timeout'))
        if request_timeout <= 0:
            raise ValueError
        return request_timeout
    except ValueError:
        raise ValueError('HTTP Request Timeout parameter must be a positive integer.')


def get_self_link(resp):
    """
    Retrieve self link from response.

    :param resp: JSON response
    :return: self link
    """
    return resp.get('_links', {}).get('self', {}).get('href', '')


def fetch_page_details(resp):
    """
    Parse total element, page number and total pages from the page.

    :param resp: json response.
    :return: page details.
    """
    total_element = resp.get('page', {}).get('totalElements', 0)
    page_number = resp.get('page', {}).get('number', 0)
    total_pages = resp.get('page', {}).get('totalPages', 0)

    return page_number, total_element, total_pages


def get_cve_context(cve_list):
    """
    Prepare CVE context data as per the Demisto standard.

    :param cve_list: cve list from response.
    :return: List of cves dictionary representing the Demisto standard context.
    """
    return [{
        'ID': cve_dict.get('cve', ''),
        'CVSS': cve_dict.get('baseScore', ''),
        'Description': cve_dict.get('summary', '')
    } for cve_dict in cve_list]


def get_ticket_context(ticket_list):
    """
    Prepare ticket context data as per the Demisto standard.

    :param ticket_list: ticket list from response.
    :return: List of ticket dictionary representing the Demisto standard context.
    """
    return [{
        'ID': ticket_dict.get('ticketNumber', ''),
        'State': ticket_dict.get('ticketStatus', '')
    } for ticket_dict in ticket_list]


def get_host_context_for_host_finding(resp_host):
    """
    Prepare host context data as per the Demisto standard.

    :param resp_host: response from host command.
    :return: Dictionary representing the Demisto standard host context.
    """
    return {
        'ID': resp_host.get('hostId', ''),
        'Hostname': resp_host.get('hostName', ''),
        'IP': resp_host.get('ipAddress', ''),
    }


def validate_values_for_between_operator(args):
    """
    Validate value of BETWEEN operator

    :param args: Demisto arguments provided by user
    :return:
    """
    operator = args.get('operator', '')
    value = args.get('value', '')

    if operator == 'BETWEEN':
        values = value.split(',')
        if len(values) != 2:
            raise ValueError('BETWEEN operator requires exact two values.')

        if not (bool(re.match(REGEX_FOR_INR_OR_FLOAT, values[0]))
                and bool(re.match(REGEX_FOR_INR_OR_FLOAT, values[1]))
                or bool(re.match(REGEX_FOR_YYYY_MM_DD, values[0]))
                and bool(re.match(REGEX_FOR_YYYY_MM_DD, values[1]))):
            raise ValueError('Value must be in number format or YYYY-MM-DD date format for BETWEEN operator.')


def get_user_id_from_integration_context(client):
    """
    Initializes a RiskSense context and set user id in context.
    User id is fetched from the Demisto's integration context is available otherwise,
    make an API call and updates integration context.

    :param client: client class object.
    :return: user id
    """
    integration_context = demisto.getIntegrationContext()

    user_id = integration_context.get('RiskSenseUserContext', {}).get('userId', '')

    if not user_id:
        url = client._base_url
        url = url.replace('/client', '/user/profile')
        resp_json = client.http_request('GET', url_suffix='', full_url=url)

        if resp_json.get('userId', ''):
            user_id = resp_json.get('userId', '')
        else:
            raise ValueError('Unable to find user Id.')

        demisto.setIntegrationContext({'RiskSenseUserContext': {'userId': user_id}})

    return user_id


def prepare_payload_for_create_tag(tag_name, client, propagate_to_all_findings):
    """
    Prepare request body (raw-json) to create tag in RiskSense.

    :param tag_name: The name of the tag.
    :param client: Client class object.
    :param propagate_to_all_findings: If the given argument is set to true, then it applies the tag to assets as well
    as findings of assets.
    :return: data in json format
    :rtype ``dict``
    """
    return {
        'fields': [
            {
                'uid': 'TAG_TYPE',
                'value': 'CUSTOM'
            },
            {
                'uid': 'NAME',
                'value': tag_name
            },
            {
                'uid': 'DESCRIPTION',
                'value': 'Tag Created for ' + tag_name
            },
            {
                'uid': 'OWNER',
                'value': get_user_id_from_integration_context(client)
            },
            {
                'uid': 'COLOR',
                'value': '#648d9f'
            },
            {
                'uid': 'PROPAGATE_TO_ALL_FINDINGS',
                'value': propagate_to_all_findings
            }
        ]
    }


def create_tag(tag_name, client_id, client, propagate_to_all_findings):
    """
    Create the tag with given tag name.

    :param tag_name: name of the tag.
    :param client_id: Client id.
    :param client: Client class object.
    :param propagate_to_all_findings: If the given argument is set to true, then it applies the tag to assets as well
    as findings of assets.
    :return: Tag Id
    """
    url_suffix = '/' + str(client_id) + '/tag'

    data = prepare_payload_for_create_tag(tag_name, client, propagate_to_all_findings)

    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)

    tag_id = resp.get('id', '')

    return tag_id if tag_id else None


def search_tag_id(tag_name, client_id, client):
    """
    Search tag in RiskSense tag API. If available then return tagID.

    :param tag_name: name of the tag to search.
    :param client_id: Client id.
    :param client: Client class object.
    """

    url_suffix = '/' + str(client_id) + '/tag/search'

    # Tag search payload
    filter_dict = {'field': 'name', 'exclusive': False, 'operator': 'EXACT', 'value': tag_name}
    data = {'filters': [filter_dict], 'projection': 'basic'}  # Only projection basic is supported.

    # Request search tag API
    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)

    tags = resp.get('_embedded', {}).get('tags', [])
    if tags:
        return tags[0].get('id')
    return None


def prepare_request_payload_for_tag(args, tag_id):
    """
    Prepare body (raw-json) for post API request.
    Used in 'risksense-apply-tag' command.

    :param args: Demisto argument provided by user
    :param tag_id: The id of the tag.
    :return: data in json format
    :rtype ``dict``
    :raises ValueError exception if required params are missing
    """
    # Fetching value of arguments.
    fieldname = args.get('fieldname', '')
    operator = args.get('operator', '')
    exclusive_operator = args.get('exclude', '').lower()
    value = args.get('value', '')
    filter_data = {}  # type: Dict[str, Any]
    filters = []  # type: List[Dict[str, Any]]
    data = {}  # type: Dict[str, Any]

    # If either of fieldname, value, operator or exculsive_operator are provided
    # then validate their required fields
    if fieldname or value or operator or exclusive_operator:
        if not fieldname:
            raise ValueError('fieldname is missing.')
        if not value:
            raise ValueError('value is missing.')
        if not operator:
            operator = 'EXACT'
        if not exclusive_operator:
            exclusive_operator = 'false'

        if operator in RISKSENSE_FIELD_MAPPINGS:
            operator = RISKSENSE_FIELD_MAPPINGS[operator]

        if fieldname in RISKSENSE_FIELD_MAPPINGS:
            fieldname = RISKSENSE_FIELD_MAPPINGS[fieldname]

        # Check validation of IP Address in case of operator = EXACT
        if fieldname == 'ipAddress' and operator == 'EXACT':
            if not is_ip_valid(value, True):
                raise ValueError('IP Address is invalid.')

        # Check validation of between operator.
        validate_values_for_between_operator(args)

        filters.append(
            {
                'field': fieldname,
                'exclusive': exclusive_operator,
                'operator': operator,
                'value': value.lower()
            }
        )
        filter_data['filters'] = filters
    data['filterRequest'] = filter_data
    data['isRemove'] = False
    data['tagId'] = tag_id
    return data


def get_apply_tag_context(resp, tag_name):
    """
    Prepare context for apply tag command.

    :param resp: response.
    :param tag_name: Name of the tag.
    :return: Dictionary of tag context.
    """

    return {
        'AssociationID': resp.get('id', ''),
        'Created': resp.get('created', ''),
        'TagName': tag_name
    }


''' REQUESTS FUNCTIONS '''


def test_module(client):
    """
    Performs basic GET request

    :param client: client object.
    :return: None
    """
    client_name = demisto.params().get('client_name', '-')
    try:
        resp_json = client.http_request('GET', url_suffix='')
    except DemistoException:
        raise ValueError("Test connectivity failed. Check the configuration parameters provided.")
    clients = resp_json.get('_embedded', {}).get('clients', [])
    # Verifying client name mentioned in integration configuration
    if not any(client_info.get('name', '') == client_name for client_info in clients):
        raise ValueError('Invalid client name configured.')
    demisto.results('ok')


def get_hosts_command(client, args):
    """
    Retrieve information about host(s) based on arguments.
    Perform sorting based on argument. By default, it will sort by 'rs3' field.

    :param client: client object
    :param args: filter criteria provided by user.
    :return: standard output.
    """
    # validate command arguments
    validate_arguments(args)

    # gather client detail from integration context
    client_detail = get_client_detail_from_context(client)
    client_id = client_detail['Id']
    client_name = client_detail['ClientName']
    url_suffix = '/' + str(client_id) + '/host/search'

    # Prepares filter request body
    data = prepare_filter_payload(args, 'detail')

    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)
    page_number, total_element, total_pages = fetch_page_details(resp)

    if total_element == 0:
        return 'No host(s) found for the given argument.', {}, {}
    if page_number >= total_pages:
        raise ValueError('Invalid page navigation.')

    resp_list_host = resp.get('_embedded', {}).get('hosts', [])
    href = get_self_link(resp)

    ec = {}  # type: Dict[str, Any]
    hr = ''

    if resp and '_embedded' in resp.keys():
        host_context = []  # type: List[Dict[str, Any]]
        host_ticket_context = []  # type: List[Dict[str, Any]]
        risksense_host_context = []  # type: List[Dict[str, Any]]
        host_details_hr = []  # type: List[Dict[str, Any]]

        hr += '### Total hosts found: ' + str(total_element) + '\t\t'
        hr += 'Page: ' + str(page_number) + '/' + str(total_pages - 1) + '\t\t'
        hr += 'Client: ' + client_name + '\n'

        for resp_host in resp_list_host:
            # creating hr
            host_details_hr.append(get_host_hr(resp_host))

            # creating Demisto's standard host context
            host_context.append(get_host_context(resp_host))

            # creating Demisto's standard ticket context
            host_ticket_context.extend(get_ticket_context(resp_host.get('tickets', [])))

            # creating RiskSense context
            risksense_host_context.append(get_risksense_host_context(href, resp_host))

        hr += tableToMarkdown('RiskSense host(s) details:', host_details_hr,
                              ['RS3', 'Host Name', 'Total Findings', 'Critical Findings', 'High Findings',
                               'Medium Findings', 'Low Findings', 'Info Findings', 'Owner', 'ID', 'OS', 'Tags',
                               'Notes', 'xRS3', 'Criticality', 'IP Address', 'Network', 'Group', 'External'],
                              removeNull=True)

        ec = {
            'Host(val.ID == obj.ID)': host_context,
            'RiskSense.Host(val.ID == obj.ID)': risksense_host_context
        }
        if host_ticket_context:
            ec['Ticket(val.ID == obj.ID)'] = host_ticket_context

    else:
        hr += 'No host(s) found for given argument.'

    return hr, ec, resp


def get_host_detail_command(client, args):
    """
    Retrieve information about particular host based on host name or host id.

    :param client: client object
    :param args: Demisto argument provided by user.
    :return: standard output.
    """
    data = prepare_payload_for_detail_commands(args)

    client_detail = get_client_detail_from_context(client)
    client_id = client_detail['Id']
    client_name = client_detail['ClientName']

    url_suffix = '/' + str(client_id) + '/host/search'
    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)

    if resp.get('page', {}).get('totalElements') == 0:
        return 'No host detail found for the given argument.', {}, {}

    hr = ''
    ec = {}  # type: Dict[str, Any]
    if resp and '_embedded' in resp.keys():
        host_context = []  # type: List[Dict[str, Any]]
        risksense_host_context = []  # type: List[Dict[str, Any]]
        host_ticket_context = []  # type: List[Dict[str, Any]]
        host_detail_dict = resp.get('_embedded', {}).get('hosts')[0]
        href = get_self_link(resp)

        # Human readable.
        hr += '### Client: ' + client_name + '\n'
        hr += get_host_detail_hr(host_detail_dict)

        # standard context.
        host_context.append(get_host_context(host_detail_dict))

        # creating Demisto's standard ticket context
        host_ticket_context.extend(get_ticket_context(host_detail_dict.get('tickets', [])))

        risksense_host_context.append(get_risksense_host_context(href, host_detail_dict))
        ec = {
            'Host(val.ID == obj.ID)': host_context,
            'RiskSense.Host(val.ID == obj.ID)': risksense_host_context
        }

        if host_ticket_context:
            ec['Ticket(val.ID == obj.ID)'] = host_ticket_context
    else:
        hr += 'No host detail found for given argument.'
    return hr, ec, resp


def get_unique_cves_command(client, args):
    """
    Retrieve unique CVEs that contains vulnerabilities based on hostfinding_id.

    :param client: client object
    :param args: Demisto argument provided by user.
    :return: standard output.
    """
    client_detail = get_client_detail_from_context(client)
    client_id = client_detail['Id']
    client_name = client_detail['ClientName']
    url_suffix = '/' + str(client_id) + '/hostFinding/search'

    data = prepare_unique_cves_payload(args)

    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)

    if resp.get('page', {}).get('totalElements') == 0:
        return 'No unique cves found for the given argument.', {}, {}

    hr = ''
    ec = {}  # type: Dict[str, Any]
    if resp and '_embedded' in resp.keys():
        host_findings = resp.get('_embedded', {}).get('hostFindings', [])
        host_findings_context = []  # type: List[Dict[str, Any]]
        host_finding_cve_context = []  # type: List[Dict[str, Any]]

        for host_finding in host_findings:
            vulnerabilities = host_finding.get('vulnerabilities', {}).get('vulnInfoList', [])

            if len(vulnerabilities) == 0:
                return 'No vulnerabilities found for the given argument.', {}, {}

            # Human readable.
            hr += '### Client: ' + client_name + '\n'
            hr += tableToMarkdown('Vulnerabilities found:', get_vulnerabilities_hr(vulnerabilities),
                                  ['Name', 'V2/Score', 'Attack Vector', 'Attack Complexity', 'Authentication',
                                   'Confidentiality Impact', 'Integrity Impact', 'Availability Impact', 'Summary'],
                                  removeNull=True)

            #  Prepare context data
            host_findings_context.extend(get_unique_cves_context(vulnerabilities, args.get('hostFindingId', '')))

            # creating Demisto's standard CVE context
            host_finding_cve_context.extend(get_cve_context(vulnerabilities))

        ec = {
            'RiskSense.UniqueVulnerabilities(val.Cve == obj.Cve && val.HostFindingID == obj.HostFindingID)':
                host_findings_context
        }
        if host_finding_cve_context:
            ec[outputPaths['cve']] = host_finding_cve_context
    else:
        hr += 'No Vulnerabilities found for a given argument.'

    return hr, ec, resp


def get_host_findings_command(client, args):
    """
    Retrieves information about host findings based on arguments.
    Finding status can be 'Open' or 'Closed'.By default return all host findings.

    :param client: Object of client class
    :param args: Demisto arguments provided by user
    :return: Standard output
    """

    # validate command arguments
    validate_arguments(args)

    client_detail = get_client_detail_from_context(client)
    client_id = client_detail['Id']
    client_name = client_detail['ClientName']
    url_suffix = '/' + str(client_id) + '/hostFinding/search'

    # Status of host findings
    status = args.get('status', '')

    data = prepare_filter_payload(args, 'detail')

    if status:
        # adding additional filters
        data = add_filter_to_request(data, 'generic_state', 'false', 'EXACT', status)

    # making final API call
    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)

    page_number, total_element, total_pages = fetch_page_details(resp)

    if total_element == 0:
        return 'No host finding(s) found for given argument(s).', {}, {}
    if page_number >= total_pages:
        raise ValueError('Invalid page navigation.')

    ec = {}  # type: Dict[str, Any]
    hr = ''

    if resp and '_embedded' in resp.keys():
        resp_list_hostfinding = resp.get('_embedded', {}).get('hostFindings', [])

        host_finding_details_hr = []  # type: List[Dict[str, Any]]
        risksense_host_finding_context = []  # type: List[Dict[str, Any]]
        host_finding_ticket_context = []  # type: List[Dict[str, Any]]
        host_finding_cve_context = []  # type: List[Dict[str, Any]]
        host_context = []  # type: List[Dict[str, Any]]

        for resp_hostfinding in resp_list_hostfinding:
            host_finding_details_hr.append(get_host_finding_hr(resp_hostfinding))
            risksense_host_finding_context.append(get_risksense_host_finding_context(resp_hostfinding))

            # creating Demisto's standard host context
            host_context.append(get_host_context_for_host_finding(resp_hostfinding.get('host', {})))

            # creating Demisto's standard ticket context
            host_finding_ticket_context.extend(get_ticket_context(resp_hostfinding.get('tickets', [])))

            # creating Demisto's standard CVE context
            host_finding_cve_context.extend(
                get_cve_context(resp_hostfinding.get('vulnerabilities', {}).get('vulnInfoList', [])))

        # human Readable
        hr += '### Total ' + status.lower() + ' host findings: ' + str(
            total_element) if status else '### Total host findings: ' + str(total_element)

        hr += '\t\t Page: ' + str(page_number) + '/' + str(total_pages - 1)
        hr += '\t\t Client: ' + client_name
        hr += '\n' + tableToMarkdown(
            status.capitalize() + ' host finding(s) details:' if status else 'Host finding(s) details:',
            host_finding_details_hr,
            ['ID', 'Host Name', 'IP Address', 'Title', 'Risk', 'Threats', 'RS3', 'Criticality',
             'Severity',
             'Groups', 'Port', 'State', 'Assignments', 'Tags', 'Asset Tags', 'Note',
             'Manual Finding Report Count'], removeNull=True)
        # context data
        ec = {
            'RiskSense.HostFinding(val.ID == obj.ID)': risksense_host_finding_context,
            'Host(val.ID == obj.ID)': host_context
        }
        if host_finding_ticket_context:
            ec['Ticket(val.ID == obj.ID)'] = host_finding_ticket_context
        if host_finding_cve_context:
            ec[outputPaths['cve']] = host_finding_cve_context
    else:
        hr += 'No host finding(s) found for given argument(s).'
    return hr, ec, resp


def get_unique_open_findings_command(client, args):
    """
    Retrieve information about open host findings based on arguments.
    Perform sorting based on argument. By default, it will sort by 'severity' field.

    :param client: client object
    :param args: demisto argument provided by user.
    :return: standard output.
    """
    # validate command arguments
    validate_arguments(args)

    client_detail = get_client_detail_from_context(client)
    client_id = client_detail['Id']
    client_name = client_detail['ClientName']
    url_suffix = '/' + str(client_id) + '/uniqueHostFinding/search'
    projection = 'basic'

    if args.get('fieldname', '') == 'Title':
        args['fieldname'] = 'title'

    if args.get('sort_by', '') == 'Title':
        args['sort_by'] = 'title'

    # preparing request payload
    data = prepare_filter_payload(args, projection)

    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)

    page_number, total_element, total_pages = fetch_page_details(resp)

    if total_element == 0:
        return 'No unique open finding(s) found for the given argument(s).', {}, {}

    if page_number >= total_pages:
        raise ValueError('Invalid page navigation.')

    unique_open_finding_context = []  # type: List[Dict[str, Any]]
    unique_open_finding_hr = []  # type: List[Dict[str, Any]]
    ec = {}  # type: Dict[str, Any]
    hr = ''
    if resp and '_embedded' in resp.keys():
        unique_open_finding_list = resp.get('_embedded', {}).get('uniqueHostFindings', [])
        href = get_self_link(resp)
        for unique_open_finding in unique_open_finding_list:
            # context
            unique_open_finding_context.append(get_unique_open_finding_context(unique_open_finding, href))

            # Human Readable
            unique_open_finding_hr.append(get_unique_open_finding_hr(unique_open_finding))

        hr += '### Total unique open findings: ' + str(total_element)
        hr += '\t\t Page: ' + str(page_number) + '/' + str(total_pages - 1)
        hr += '\t\t Client: ' + client_name + '\n'
        hr += tableToMarkdown('Unique open finding(s) details:', unique_open_finding_hr,
                              ['Title', 'Severity', 'Asset Count', 'Source', 'Source ID'], removeNull=True)

        ec = {
            'RiskSense.UniqueHostFinding': unique_open_finding_context
        }
    else:
        hr += 'No unique open finding(s) found for given argument(s).'

    return hr, ec, resp


def get_apps_command(client, args):
    """
   Retrieve information about applications based on arguments.
   Perform sorting based on argument. By default, it will sort by 'Name' field.

   :param client: Client object
   :param args: Demisto argument(s) provided by user.
   :return: standard output.
   """

    # validate command arguments
    validate_arguments(args)

    client_detail = get_client_detail_from_context(client)
    client_id = client_detail['Id']
    client_name = client_detail['ClientName']
    url_suffix = '/' + str(client_id) + '/application/search'
    projection = 'detail'

    data = prepare_filter_payload(args, projection)

    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)
    apps_context = []  # type: List[Dict[str, Any]]
    apps_hr = []  # type: List[Dict[str, Any]]
    ec = {}  # type: Dict[str, Any]
    hr = ''

    page_number, total_element, total_pages = fetch_page_details(resp)
    if total_element == 0:
        return 'No application(s) found for the given arguments.', {}, {}

    if page_number >= total_pages:
        raise ValueError('Invalid page navigation.')

    if resp and '_embedded' in resp.keys():
        href = get_self_link(resp)
        apps_list = resp.get('_embedded', {}).get('applications', [])
        app_ticket_context = []  # type: List[Dict[str, Any]]

        for app in apps_list:
            # Context
            get_apps_context(apps_context, app, href)

            # creating Demisto's standard ticket context
            app_ticket_context.extend(get_ticket_context(app.get('tickets', [])))

            # Human Readable
            apps_hr.append(get_apps_hr(app))

        hr += '### Total applications: ' + str(total_element) + '\t\t'
        hr += 'Page: ' + str(page_number) + '/' + str(total_pages - 1)
        hr += '\t\tClient: ' + client_name + '\n'

        hr += tableToMarkdown('RiskSense application(s) details:', apps_hr,
                              ['ID', 'Address', 'Name', 'Network', 'Total Findings', 'Critical Findings',
                               'High Findings', 'Medium Findings', 'Low Findings', 'Info Findings', 'Groups', 'URLs',
                               'Tags', 'Notes'], removeNull=True)
        ec = {
            'RiskSense.Application(val.ID == obj.ID)': apps_context
        }
        if app_ticket_context:
            ec['Ticket(val.ID == obj.ID)'] = app_ticket_context
    else:
        hr += 'No application(s) found for given argument.'

    return hr, ec, resp


def get_host_finding_detail_command(client, args):
    """
    Retrieve information about particular host finding based on host finding id.

    :param client: object of client
    :param args: Demisto arguments provided by the user
    :return: command output
    """
    client_detail = get_client_detail_from_context(client)
    client_id = client_detail['Id']
    client_name = client_detail['ClientName']
    url_suffix = '/' + str(client_id) + '/hostFinding/search'
    data = prepare_payload_for_detail_commands(args)
    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)
    total_element = resp.get('page', {}).get('totalElements', '')

    if total_element == 0:
        return 'No host finding details found for the given argument.', {}, {}

    ec = {}  # type: Dict[str, Any]
    hr = ''
    if resp and '_embedded' in resp.keys():
        host_finding_detail = resp.get('_embedded', {}).get('hostFindings', '')[0]
        host_finding_ticket_context = []  # type: List[Dict[str, Any]]
        host_finding_cve_context = []  # type: List[Dict[str, Any]]
        host_context = []  # type: List[Dict[str, Any]]
        risksense_host_finding_context = [
            get_risksense_host_finding_context(host_finding_detail)]  # type: List[Dict[str, Any]]

        # creating Demisto's standard host context
        host_context.append(get_host_context_for_host_finding(host_finding_detail.get('host', {})))

        # creating Demisto's standard ticket context
        host_finding_ticket_context.extend(get_ticket_context(host_finding_detail.get('tickets', [])))

        # creating Demisto's standard CVE context
        host_finding_cve_context.extend(
            get_cve_context(host_finding_detail.get('vulnerabilities', {}).get('vulnInfoList', [])))

        # Human Readable.
        hr += '### Client: ' + client_name + '\n'
        hr += get_host_finding_detail_hr(host_finding_detail)

        # context.
        ec = {
            'RiskSense.HostFinding(val.ID == obj.ID)': risksense_host_finding_context,
            'Host(val.ID == obj.ID)': host_context
        }
        if host_finding_ticket_context:
            ec['Ticket(val.ID == obj.ID)'] = host_finding_ticket_context
        if host_finding_cve_context:
            ec[outputPaths['cve']] = host_finding_cve_context
    else:
        hr += 'No host finding details found for given argument.'

    return hr, ec, resp


def get_app_detail_command(client, args):
    """
    Retrieve information about particular application based on application id.

    :param client: client object
    :param args: demisto argument provided by user.
    :return: command output.
    """
    data = prepare_payload_for_detail_commands(args)
    client_detail = get_client_detail_from_context(client)
    client_id = client_detail['Id']
    client_name = client_detail['ClientName']
    url_suffix = '/' + str(client_id) + '/application/search'
    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)
    hr = ''
    ec = {}  # type: Dict[str, Any]

    if resp.get('page', {}).get('totalElements') == 0:
        return 'No application detail found for the given argument.', {}, {}

    if resp and '_embedded' in resp.keys():
        app_detail_context = []  # type: List[Dict[str, Any]]
        app_ticket_context = []  # type: List[Dict[str, Any]]
        app_detail_dict = resp.get('_embedded', {}).get('applications')[0]
        href = get_self_link(resp)

        # Human readable.
        hr += '### Client: ' + client_name + '\n'
        hr += get_app_detail_hr(app_detail_dict)

        # Context.
        get_apps_context(app_detail_context, app_detail_dict, href)

        # creating Demisto's standard ticket context
        app_ticket_context.extend(get_ticket_context(app_detail_dict.get('tickets', [])))

        ec = {
            'RiskSense.Application(val.ID == obj.ID)': app_detail_context
        }
        if app_ticket_context:
            ec['Ticket(val.ID == obj.ID)'] = app_ticket_context
    else:
        hr += 'No application detail found for given argument.'

    return hr, ec, resp


def apply_tag_command(client, args):
    """
    Apply new or existing tag to asset, creates a new tag if it does not exist in RiskSense.

    :param client: client object
    :param args: demisto argument provided by user.
    :return: command output.
    """
    client_detail = get_client_detail_from_context(client)
    client_id = client_detail['Id']
    asset_type = args.get('assettype', '')
    url_suffix = '/' + str(client_id) + '/' + asset_type + '/tag'
    tag_name = args.get('tagname', '')
    propagate_to_all_findings = args.get('propagate_to_all_findings', 'false')

    if args.get('exclude', 'false').lower() not in ['true', 'false']:
        raise ValueError('Exclude argument should be either true or false.')

    if propagate_to_all_findings.lower() not in ['true', 'false']:
        raise ValueError('Value of propagate_to_all_findings argument should be either true or false.')

    # Check special character in tag name.
    if bool(re.match(r'[`*+=\\.;,\'\"@!#$%^&*()<>?/\|}{\]\[~]', tag_name)):
        raise ValueError('No special characters are allowed in the tag name.')

    # Check tag name length.
    if len(tag_name) < 2:
        raise ValueError('Tag name must be at least 2 characters.')

    tag_id = search_tag_id(tag_name, client_id, client)
    hr = ''
    ec = {}  # type: Dict[str, Any]
    if not tag_id:
        tag_id = create_tag(tag_name, client_id, client, propagate_to_all_findings)
        if not tag_id:
            raise ValueError('Unable to Create tag.')

    data = prepare_request_payload_for_tag(args, tag_id)

    resp = client.http_request('POST', url_suffix=url_suffix, json_data=data)

    if resp:
        # Human Readable
        hr += '### ' + tag_name + ' tag applied to given asset(s).'

        # Context.
        ec = {
            'RiskSense.TagAssociation(val.AssociationID == obj.AssociationID)': get_apply_tag_context(resp, tag_name)
        }
    else:
        hr += '### Unable to apply tag.'

    return hr, ec, resp


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    api_key = params.get('api_key')

    # Service base URL
    base_url = urljoin(params['url'], '/api/v1/client')
    # Request timeout
    request_timeout = get_request_timeout()

    # Should we use SSL
    use_ssl = not params.get('insecure', False)

    # Should we use system proxy settings
    use_proxy = params.get('proxy')

    # Headers to be sent in requests
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Initialize Client object
    client = Client(base_url, request_timeout, verify=use_ssl, proxy=use_proxy, headers=headers)
    command = demisto.command()

    # Commands dict
    commands = {
        'risksense-get-hosts': get_hosts_command,
        'risksense-get-host-detail': get_host_detail_command,
        'risksense-get-unique-cves': get_unique_cves_command,
        'risksense-get-host-findings': get_host_findings_command,
        'risksense-get-unique-open-findings': get_unique_open_findings_command,
        'risksense-get-apps': get_apps_command,
        'risksense-get-host-finding-detail': get_host_finding_detail_command,
        'risksense-get-app-detail': get_app_detail_command,
        'risksense-apply-tag': apply_tag_command
    }
    # Run the commands
    try:
        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))

    except Exception as e:
        return_error('Failed to execute {} command.\nError: {}'.format(demisto.command(), str(e)))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
