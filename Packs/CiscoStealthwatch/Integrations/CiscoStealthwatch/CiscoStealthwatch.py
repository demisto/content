import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
import requests
import dateparser
from datetime import datetime

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Cisco Stelathwatch Client.
    """

    def __init__(self, base_url: str, auth: tuple, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, auth=auth, verify=verify, proxy=proxy)

    def prepare_request(self, url_suffix: str, method: str = 'GET', data: dict = {}, json_data: dict = {},
                        resp_type: str = 'json'):
        cookies = self._get_cookies()
        headers = {}
        if token := cookies.get('XSRF-TOKEN'):
            demisto.debug('Received XSRF-TOKEN cookie from Cisco Secure Network, creating an X-XSRF-TOKEN header.')
            headers.update({'X-XSRF-TOKEN': token})
        return self._http_request(method=method, url_suffix=url_suffix, json_data=json_data, data=data, cookies=cookies,
                                  headers=headers, resp_type=resp_type)

    def list_tenants(self):
        return self.prepare_request(method='GET', url_suffix='/sw-reporting/v1/tenants')

    def get_tenant(self, tenant_id: str):
        return self.prepare_request(method='GET', url_suffix=f'/sw-reporting/v1/tenants/{tenant_id}')

    def list_tags(self, tenant_id: str):
        return self.prepare_request(method='GET',
                                    url_suffix=f'/sw-reporting/v1/tenants/{tenant_id}'
                                               f'/internalHosts/tags')

    def get_tag(self, tenant_id: str, tag_id: str):
        url = f'/smc-configuration/rest/v1/tenants/{tenant_id}/tags/{tag_id}'
        return self.prepare_request(method='GET', url_suffix=url)

    def tag_hourly_traffic(self, tenant_id: str, tag_id: str):
        url = f'/sw-reporting/v1/tenants/{tenant_id}/internalHosts/tags/{tag_id}/traffic/hourly'
        return self.prepare_request(method='GET', url_suffix=url)

    def get_top_alarms(self, tenant_id: str):
        url = f'/sw-reporting/v1/tenants/{tenant_id}/internalHosts/alarms/topHosts'
        return self.prepare_request(method='GET', url_suffix=url)

    def initialize_flow_search(self, tenant_id: str, data) -> dict:
        url = f'/sw-reporting/v2/tenants/{tenant_id}/flows/queries'
        return self.prepare_request(method='POST', url_suffix=url, json_data=data)

    def check_flow_search_progress(self, tenant_id: str, search_id: str):
        url = f'/sw-reporting/v2/tenants/{tenant_id}/flows/queries/{search_id}'
        return self.prepare_request(method='GET', url_suffix=url)

    def get_flow_search_results(self, tenant_id, search_id):
        url = f'/sw-reporting/v2/tenants/{tenant_id}/flows/queries/{search_id}/results'
        return self.prepare_request(method='GET', url_suffix=url)

    def initialize_security_events_search(self, tenant_id: str, data) -> dict:
        url = f'/sw-reporting/v1/tenants/{tenant_id}/security-events/queries'
        return self.prepare_request(method='POST', url_suffix=url, json_data=data)

    def check_security_events_search_progress(self, tenant_id: str, search_id: str):
        url = f'/sw-reporting/v1/tenants/{tenant_id}/security-events/queries/{search_id}'
        return self.prepare_request(method='GET', url_suffix=url)

    def get_security_events_search_results(self, tenant_id, search_id):
        url = f'/sw-reporting/v1/tenants/{tenant_id}/security-events/results/{search_id}'
        return self.prepare_request(method='GET', url_suffix=url)

    def _get_cookies(self) -> requests.cookies.RequestsCookieJar:
        data = {
            'username': self._auth[0],
            'password': self._auth[1]
        }

        response = self._http_request(method='POST',
                                      url_suffix='/token/v2/authenticate',
                                      data=data,
                                      resp_type='response')
        return response.cookies


def cisco_stealthwatch_query_flows_initialize_command(client: Client, tenant_id: str,
                                                      start_time: str = None, end_time: str = None,
                                                      time_range: str = None, limit: str = None,
                                                      ip_addresses: str = None) -> CommandResults:
    """Initialize the process of query flows with user params and returns the id of the search
    to retrieve its results

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant we want to search with
        start_time (str, optional): The start time of the search. Defaults to None.
        end_time (str, optional): The end time of the search. Defaults to None.
        time_range (str, optional): Time range (start and end) of the search. Defaults to None.
        limit (str, optional): Number of records to return. Defaults to None.
        ip_addresses (str, optional): The IP addresses to search for. Defaults to None.

    Returns:
        CommandResults: Raw response, outputs and readable outputs.
    """
    # must provide start_time, time_range or start_time and end_time. else: throw error.
    if not (start_time or end_time or time_range):
        raise Exception('Must provide start_time, time_range, or start_time and end_time')
    if not (time_range or start_time) and end_time:
        raise Exception('Must provide start_time, time_range, or start_time and end_time')

    # formatting start_time and end_time
    start_time, end_time = times_handler(start_time, end_time, time_range)
    if not start_time:
        raise Exception('Invalid time format. Check: start_time, time_range, and end_time')

    data = remove_empty_elements({
        "startDateTime": start_time,
        "endDateTime": end_time,
        "recordLimit": limit,
        "subject": {
            "ipAddresses": {
                "includes": ip_addresses if isinstance(ip_addresses, list) else [ip_addresses]
            }
        }
    })
    response = client.initialize_flow_search(tenant_id, data)
    outputs = dict_safe_get(response, ['data', 'query'])
    table = tableToMarkdown('Query Flows Initializing Information:', outputs,
                            headers=['id', 'status', 'percentComplete'], removeNull=True,
                            headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix='CiscoStealthwatch.FlowStatus',
        outputs_key_field='id',
        raw_response=response,
        outputs=outputs,
        readable_output=table)


def cisco_stealthwatch_query_flows_status_command(client: Client, tenant_id: str,
                                                  search_id: str) -> CommandResults:
    """Retrieve query flow status using search id

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant the search was performed on
        search_id (str): The id of the search

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    response = client.check_flow_search_progress(tenant_id, search_id)
    outputs = dict_safe_get(response, ['data', 'query'])
    outputs['id'] = search_id
    table = tableToMarkdown('Query Flows Status Information:', outputs,
                            headers=['id', 'percentComplete'], removeNull=True,
                            headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix='CiscoStealthwatch.FlowStatus',
        outputs_key_field='id',
        raw_response=response,
        outputs=outputs,
        readable_output=table)


def cisco_stealthwatch_query_flows_results_command(client: Client, tenant_id: str,
                                                   search_id: str) -> CommandResults:
    """Retrieve the results for a query flow by search id

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant the search was performed on
        search_id (str): The id of the search

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    response = client.get_flow_search_results(tenant_id, search_id)
    outputs = []
    for data in dict_safe_get(response, ['data', 'flows']):
        outputs.append(data)
    headers = ['id', 'tenantId', 'flowCollectorId', 'protocol', 'serviceId', 'statistics', 'peer',
               'subject']
    table = tableToMarkdown('Query Flows Results Information:', outputs, headers=headers,
                            removeNull=True, headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix='CiscoStealthwatch.FlowResults',
        outputs_key_field='id',
        raw_response=response,
        outputs=outputs,
        readable_output=table
    )


def cisco_stealthwatch_list_tags_command(client: Client, tenant_id: str) -> CommandResults:
    """List tags (called host groups on the Stealthwatch API) based on tenant id

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant to list its tags (tenant is a domain on the API)

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    response = client.list_tags(tenant_id)
    outputs = []
    for tag in response.get('data', []):
        outputs.append(tag)

    outputs = sorted(outputs, key=lambda x: x.get('id'))

    table = tableToMarkdown(f'Tags for tenant_id: {tenant_id}:', outputs,
                            headers=['displayName', 'id'], removeNull=True,
                            headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='CiscoStealthwatch.Tag',
        outputs_key_field='id',
        raw_response=response,
        outputs=outputs,
        readable_output=table
    )


def cisco_stealthwatch_get_tag_command(client: Client, tenant_id: str, tag_id: str)\
        -> CommandResults:
    """Get a single tag (called host group on the Stealthwatch API) information

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant to get its tag information
        tag_id (str): The id of the tag to retrieve its information

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    response = client.get_tag(tenant_id, tag_id)
    outputs = response.get('data', {})

    table = tableToMarkdown(f'Tag {tag_id} with tenant id {tenant_id} results:', outputs,
                            headers=['id', 'name', 'location', 'domainId'],
                            removeNull=True, headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='CiscoStealthwatch.Tag',
        outputs_key_field='id',
        raw_response=response,
        outputs=outputs,
        readable_output=table
    )


def cisco_stealthwatch_list_tenants_command(client: Client,
                                            tenant_id: str = None) -> CommandResults:
    """List all tenants (called domains on the Stealthwatch API)

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant to retrieve its information

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    if tenant_id:
        response = client.get_tenant(tenant_id)
        outputs = response.get('data', [])

        table = tableToMarkdown(f'Tenant {tenant_id}:', outputs,
                                headers=['id', 'displayName'], removeNull=True,
                                headerTransform=pascalToSpace)

        command_results = CommandResults(
            outputs_prefix='CiscoStealthwatch.Tenant',
            outputs_key_field='id',
            raw_response=response,
            outputs=outputs,
            readable_output=table
        )
    else:
        response = client.list_tenants()
        outputs = []
        for tenant in response.get('data', []):
            outputs.append(tenant)

        table = tableToMarkdown('Tenants:', outputs, headers=['id', 'displayName'], removeNull=True,
                                headerTransform=pascalToSpace)

        command_results = CommandResults(
            outputs_prefix='CiscoStealthwatch.Tenant',
            outputs_key_field='id',
            raw_response=response,
            outputs=outputs,
            readable_output=table
        )
    return command_results


def cisco_stealthwatch_get_tag_hourly_traffic_report_command(client: Client, tenant_id: str,
                                                             tag_id: str) -> CommandResults:
    """Get a tag (called host group on the Stealthwatch API) hourly traffic report

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant to retrieve its information
        tag_id (str): The id of the tag to retrieve its information

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    response = client.tag_hourly_traffic(tenant_id, tag_id)
    outputs = []
    if response.get('data'):
        for report in response['data'].get('data', []):
            report['tag_id'] = tag_id
            report['tenant_id'] = tenant_id
            value = report.get('value')
            report.pop('value')
            report.update(value)
            outputs.append(report)

    headers = ['timestamp', 'inboundByteCount', 'outboundByteCount', 'withinByteCount']
    title = f'Hourly Tag Traffic Report for tenant id {tenant_id} and tag id {tag_id}:'
    table = tableToMarkdown(title, outputs, headers=headers, removeNull=True,
                            headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='CiscoStealthwatch.TagHourlyTraffic',
        outputs_key_field=['tag_id', 'tenant_id', 'timestamp'],
        raw_response=response,
        outputs=outputs,
        readable_output=table
    )


def cisco_stealthwatch_get_top_alarming_tags_command(client: Client,
                                                     tenant_id: str) -> CommandResults:
    """Get top alarming tags (called host groups on the Stealthwatch API)

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant to retrieve its information

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    response = client.get_top_alarms(tenant_id)

    outputs = []
    for alarm in dict_safe_get(response, ['data', 'data'], []):
        alarm['tenant_id'] = tenant_id
        outputs.append(alarm)

    headers = ['hostGroupIds', 'ipAddress', 'sourceCategoryEvents']
    title = f'Top Alarming Tags for tenant id {tenant_id}:'
    table = tableToMarkdown(title, outputs, headers=headers, removeNull=True,
                            headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='CiscoStealthwatch.AlarmingTag',
        outputs_key_field=['tenant_id', 'hostGroupIds'],
        raw_response=response,
        outputs=outputs,
        readable_output=table
    )


def cisco_stealthwatch_list_security_events_initialize_command(client: Client, tenant_id: str,
                                                               start_time: str = None,
                                                               end_time: str = None,
                                                               time_range: str = None) \
        -> CommandResults:
    """Initialization of the security events list process.

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant to retrieve its information
        start_time (str, optional): Start time for request params. Defaults to None.
        end_time (str, optional): End time for request params. Defaults to None.
        time_range (str, optional): Time range (start and end) for request params. Defaults to None.

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    # must provide start_time, time_range or start_time and end_time. else: throw error.
    if not (start_time or end_time or time_range):
        raise Exception('Must provide start_time, time_range, or start_time and end_time')
    if not (time_range or start_time) and end_time:
        raise Exception('Must provide start_time, time_range, or start_time and end_time')

    # formatting start_time and end_time
    start_time, end_time = times_handler(start_time, end_time, time_range)
    if not start_time:
        raise Exception('Invalid time format. Check: start_time, time_range, and end_time')
    data = {
        "timeRange": {
            "from": start_time,
            "to": end_time
        }
    }
    response = client.initialize_security_events_search(tenant_id, data)
    outputs = dict_safe_get(response, ['data', 'searchJob'])
    table = tableToMarkdown('Security Events Initializing Information:', outputs,
                            headers=['id', 'searchJobStatus', 'percentComplete'], removeNull=True,
                            headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix='CiscoStealthwatch.SecurityEventStatus',
        outputs_key_field='id',
        raw_response=response,
        outputs=outputs,
        readable_output=table)


def cisco_stealthwatch_list_security_events_status_command(client: Client, tenant_id: str,
                                                           search_id: str) -> CommandResults:
    """Retrieve the status of the security events process using search id

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant of the security events process
        search_id (str): The if of the search.

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    response = client.check_security_events_search_progress(tenant_id, search_id)
    outputs = response.get('data', {})
    outputs['id'] = search_id
    table = tableToMarkdown('Security Events Status Information:', outputs,
                            headers=['id', 'percentComplete'], removeNull=True,
                            headerTransform=pascalToSpace)
    return CommandResults(
        outputs_prefix='CiscoStealthwatch.SecurityEventStatus',
        outputs_key_field='id',
        raw_response=response,
        outputs=outputs,
        readable_output=table)


def cisco_stealthwatch_list_security_events_results_command(client: Client, tenant_id: str,
                                                            search_id: str,
                                                            limit: int) -> CommandResults:
    """Retrieve the results of the security events process using search id

    Args:
        client (Client): Cisco Stealthwatch Client
        tenant_id (str): The id of the tenant of the security events process
        search_id (str): The id of the search
        limit (int): security events limit

    Returns:
        CommandResults: Raw response, outputs and readable outputs
    """
    response = client.get_security_events_search_results(tenant_id, search_id)

    outputs = []
    if response.get('data'):
        for security_event in dict_safe_get(response, ['data', 'results'], []):
            outputs.append(security_event)

    outputs = outputs[:int(limit)]
    headers = ['id', 'domainId', 'deviceId', 'securityEventType', 'firstActiveTime',
               'lastActiveTime', 'source', 'target', 'details', 'hitCount']
    title = f'Showing {len(outputs)} Security Events:'
    table = tableToMarkdown(title, outputs, headers=headers, removeNull=True,
                            headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='CiscoStealthwatch.SecurityEventResults',
        outputs_key_field='id',
        raw_response=response,
        outputs=outputs,
        readable_output=table
    )


def times_handler(start_time: str = None, end_time: str = None, time_range: str = None):
    """Handle the times when start_time, end_time and range needs to be start_time and end_time

    Args:
        start_time (str, optional): Start time from the user. Defaults to None.
        end_time (str, optional): End time from the user. Defaults to None.
        time_range (str, optional): Time range from the user. Defaults to None.

    Returns:
        Start time and end time from the user params with priority to time range.
    """
    start_time_obj = dateparser.parse(time_range) if time_range \
        else dateparser.parse(start_time)  # type: ignore
    end_time_obj = dateparser.parse(end_time) if end_time else datetime.now()

    start_time_obj = start_time_obj.utcfromtimestamp(start_time_obj.timestamp())  # type: ignore
    end_time_obj = end_time_obj.utcfromtimestamp(end_time_obj.timestamp())  # type: ignore
    return start_time_obj.strftime(DATE_FORMAT), end_time_obj.strftime(DATE_FORMAT)


def test_module(client):
    """Tests API connectivity and authentication'
       Returning 'ok' indicates that the integration works like it is supposed to.
       Connection to the service is successful.
    """

    try:
        client.list_tenants()
        return 'ok'
    except Exception as error:
        if 'Unauthorized' in str(error):
            return 'Authorization Error: Check Credentials arguments'
        if 'requests.exceptions.ConnectionError' in str(error):
            return 'Connection Error: Check Server URL argument'
        raise error


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')

    # get the service API url
    base_url = params.get('server_url')

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    command = demisto.command()

    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            auth=(username, password),
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'cisco-stealthwatch-query-flows-initialize':
            return_results(
                cisco_stealthwatch_query_flows_initialize_command(client, **demisto.args()))

        elif command == 'cisco-stealthwatch-query-flows-status':
            return_results(cisco_stealthwatch_query_flows_status_command(client, **demisto.args()))

        elif command == 'cisco-stealthwatch-query-flows-results':
            return_results(cisco_stealthwatch_query_flows_results_command(client, **demisto.args()))

        elif command == 'cisco-stealthwatch-list-tags':
            return_results(cisco_stealthwatch_list_tags_command(client, **demisto.args()))

        elif command == 'cisco-stealthwatch-get-tag':
            return_results(cisco_stealthwatch_get_tag_command(client, **demisto.args()))

        elif command == 'cisco-stealthwatch-list-tenants':
            return_results(cisco_stealthwatch_list_tenants_command(client, **demisto.args()))

        elif command == 'cisco-stealthwatch-get-tag-hourly-traffic-report':
            return_results(
                cisco_stealthwatch_get_tag_hourly_traffic_report_command(client, **demisto.args()))

        elif command == 'cisco-stealthwatch-get-top-alarming-tags':
            return_results(
                cisco_stealthwatch_get_top_alarming_tags_command(client, **demisto.args()))

        elif command == 'cisco-stealthwatch-list-security-events-initialize':
            return_results(
                cisco_stealthwatch_list_security_events_initialize_command(client,
                                                                           **demisto.args()))

        elif command == 'cisco-stealthwatch-list-security-events-status':
            return_results(cisco_stealthwatch_list_security_events_status_command(client,
                                                                                  **demisto.args()))

        elif command == 'cisco-stealthwatch-list-security-events-results':
            return_results(
                cisco_stealthwatch_list_security_events_results_command(client, **demisto.args()))

    # Log exceptions
    except Exception as error:
        if 'Entity not found.' in str(error) or 'Not Found.' in str(error):
            return_results("Entity not found: one or more of the IDs you've entered is illegal, "
                           "or was not found.")
        else:
            return_error(f'Failed to execute {demisto.command()} command. Error: {str(error)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
