from typing import Callable, Dict

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, apitoken: str, use_ssl: bool, use_proxy: bool):
        headers = {'X-Auth-Token': apitoken, 'Accept': 'application/json', 'Content-Type': 'application/json'}
        super().__init__(base_url, headers=headers, verify=use_ssl, proxy=use_proxy)

    def http_request(self, url: str, method: str, params: dict = None, json_data: dict = None,
                     ok_codes: tuple = (200, 204)):
        """
        initiates a http request to openphish
        """
        data = self._http_request(
            method=method,
            ok_codes=ok_codes,
            url_suffix=url,
            params=params,
            return_empty_response=True,
            json_data=json_data,
            timeout=30,
        )
        return data

    def get_sensors(self, id: str = None, hostname: str = None, ipaddr: str = None,
                    groupid: str = None, inactive_filter_days: str = None, limit: int = None) -> List[dict]:
        url = f'/v1/sensor/{id}' if id else '/v1/sensor'
        query_fields = ['ipaddr', 'hostname', 'groupid', 'inactive_filter_days']
        query_params: dict = {key: locals().get(key) for key in query_fields if
                              locals().get(key)}
        res = self.http_request(url=url, method='GET', params=query_params, ok_codes=(200, 204))
        # When querying specific sensor without filters, the api returns dictionary.
        if not isinstance(res, list):
            res = [res]
        return res

    def get_alerts(self, status: str = None, username: str = None, feedname: str = None,
                   hostname: str = None, report: str = None, sort: str = None, query: str = None,
                   facet: str = None, rows: str = None, start: str = None) -> dict:
        query_fields = ['status', 'username', 'feedname', 'hostname', 'report', 'query']
        local_params = locals()
        query_params = {key: local_params.get(key) for key in query_fields if local_params.get(key)}
        query_string = _create_query_string(**query_params)
        params = assign_params(q=query_string,
                               rows=rows,
                               start=start,
                               sort=sort,
                               facet=facet,
                               )

        return self.http_request(url='/v2/alert', method='GET', params=params)

    def get_binaries(self, md5: str = None, product_name: str = None, signed: str = None, group: str = None,
                     hostname: str = None, digsig_publisher: str = None, company_name: str = None, sort: str = None,
                     observed_filename: str = None, query: str = None, facet: str = None,
                     facet_field: str = None, rows: str = None, start: str = None) -> dict:
        query_fields = ['product_name', 'signed', 'group', 'hostname', 'digsig_publisher', 'company_name',
                        'observed_filename', 'query']
        local_params = locals()
        query_params = {key: local_params.get(key) for key in query_fields if local_params.get(key)}
        query_string = _create_query_string(query_params)
        params = assign_params(q=query_string,
                               rows=rows,
                               start=start,
                               sort=sort,
                               facet=facet,
                               )
        if facet_field:
            params['facet.field'] = facet_field
        return self.http_request(url='/v1/binary', method='GET', params=params)

    def get_processes(self, process_name: str = None, group: str = None, hostname: str = None,
                      parent_name: str = None, process_path: str = None, md5: str = None,
                      query: str = None, group_by: str = None, sort: str = None, facet: str = None,
                      facet_field: str = None, rows: str = None, start: str = None):
        query_fields = ['process_name', 'group', 'hostname', 'parent_name', 'process_path', 'md5', 'query']
        local_params = locals()
        query_params = {key: local_params.get(key) for key in query_fields if local_params.get(key)}
        query_string = _create_query_string(query_params)
        params = assign_params(q=query_string,
                               rows=rows,
                               start=start,
                               sort=sort,
                               facet=facet,
                               )
        if facet_field:
            params['facet.field'] = facet_field
        if facet_field:
            params['cb.group'] = group_by
        return self.http_request(url='/v1/process', method='GET', params=params)


''' HELPER FUNCTIONS '''


def _create_query_string(params: dict) -> str:
    current_query = [f"({params.get('query')})"] if params.get('query') else []
    if 'query' in params:
        params.pop('query')
    current_query += [f"{query_field}:{params[query_field]}" for query_field in params]
    current_query = ' AND '.join(current_query)

    if not current_query:
        raise Exception(
            f'Search without any filter is not permitted. Please add one of the following filters: {params.keys()}')

    return current_query


def _get_sensor_isolation_change_body(client: Client, sensor_id: str, new_isolation: bool) -> dict:
    new_sensor_data: dict = client.get_sensors(sensor_id)[0]
    new_sensor_data['network_isolation_enabled'] = new_isolation
    return new_sensor_data


def _parse_field(raw_field: str, sep: str = ',', index_after_split: int = 0, chars_to_remove: str = '') -> str:
    try:
        new_field = raw_field.split(sep)[index_after_split]
    except IndexError:
        raise IndexError(f'raw: {raw_field}, splitted by {sep} has no index {index_after_split}')
    chars_to_remove = set(chars_to_remove)
    for char in chars_to_remove:
        new_field = new_field.replace(char, '')
    return new_field


def _get_isolation_status_field(isolation_activated: bool, is_isolated: bool) -> str:
    if isolation_activated:
        sensor_isolation_status = 'Yes' if is_isolated else 'Pending isolation'
    else:
        sensor_isolation_status = 'Pending unisolation' if is_isolated else 'No'

    return sensor_isolation_status


''' COMMAND FUNCTIONS '''


def unquarantine_device_command(client: Client, sensor_id: str) -> CommandResults:
    url = f'/v1/sensor/{sensor_id}'
    res = client.http_request(url=url, method='PUT',
                              json_data=_get_sensor_isolation_change_body(client, sensor_id, False))
    if not res:
        raise Exception('could not run')
    return CommandResults(readable_output='Sensor was un-isolated successfully.')


def quarantine_device_command(client: Client, sensor_id: str) -> CommandResults:
    url = f'/v1/sensor/{sensor_id}'
    res = client.http_request(url=url, method='PUT',
                              json_data=_get_sensor_isolation_change_body(client, sensor_id, True))
    if not res:
        raise Exception('could not run')
    return CommandResults(readable_output='Sensor was isolated successfully.')


def sensors_list_command(client: Client, id: str = None, hostname: str = None, ip: str = None,
                         group_id: str = None, inactive_filter_days: str = None, limit: int = None) -> CommandResults:
    try:
        res = client.get_sensors(id, hostname, ip, group_id, inactive_filter_days, limit)

        res = res[:limit]

        return CommandResults(outputs=res, outputs_prefix='CBSensors', outputs_key_field='id',
                              readable_output=tableToMarkdown('Sensors', res), raw_response=res)
    except DemistoException as e:
        if '404' in e.message:
            raise Exception(f'The sensor {id} could not be found. Please try using a different sensor.')
        else:
            raise Exception(f'Error connecting to API. Error: {e.message}')


def watchlist_delete_command(client: Client, id: str) -> CommandResults:
    res = client.http_request(url=f'/v1/watchlist/{id}', method='DELETE')
    return CommandResults(readable_output=res.get('result'))


def watchlist_update_command(client: Client, id: str, search_query: str, description: str,
                             enabled: bool) -> CommandResults:
    params = assign_params(enabled=enabled, search_query=search_query, description=description)
    res = client.http_request(url=f'/v1/watchlist/{id}', method='PUT', json_data=params)
    return CommandResults(readable_output=res.get('result'))


def watchlist_create_command(client: Client, name: str, search_query: str, index_type: str = 'events',
                             description: str = '') -> CommandResults:
    params = assign_params(name=name, search_query=search_query, description=description, index_type=index_type)
    res = client.http_request(url='/v1/watchlist', method='POST', json_data=params)
    id = res.get('id')
    if id:
        return CommandResults(outputs=res, outputs_prefix='CBWatchList', outputs_key_field='id',
                              readable_output=f"Successfully created new watchlist with id {id}")
    return CommandResults(readable_output="Could not create new watchlist.")


def get_watchlist_list_command(client: Client, id: str = None) -> CommandResults:
    url = f'/v1/watchlist/{id}' if id else '/v1/watchlist'
    res = client.http_request(url=url, method='GET')
    return CommandResults(outputs=res, outputs_prefix='CBWatchList', outputs_key_field='id',
                          readable_output=tableToMarkdown('Watchlists', res))


def binary_ban_command(client: Client, md5: str, text: str, last_ban_time: str, ban_count: str, last_ban_host: str,
                       enabled: bool) -> CommandResults:
    body = assign_params(md5hash=md5,
                         text=text, last_ban_time=last_ban_time, ban_count=ban_count,
                         last_ban_host=last_ban_host, enabled=enabled)
    client.http_request(url='/v1/banning/blacklist', method='POST', json_data=body)
    return CommandResults(readable_output='hash banned successfully')


def binary_bans_list_command(client: Client) -> CommandResults:
    res = client.http_request(url='/v1/banning/blacklist', method='GET')
    return CommandResults(outputs=res, outputs_prefix='CBBanedHashes', outputs_key_field='md5',
                          readable_output=tableToMarkdown('Bans list', res))


def alert_update_command(client: Client, alert_ids: str, status: str = None, set_ignored: bool = None,
                         query: str = None) -> CommandResults:
    url = '/v1/alerts'
    body = assign_params(alert_ids=argToList(alert_ids),
                         requested_status=status,
                         set_ignored=set_ignored,
                         query=query
                         )
    res = client.http_request(url=url, method='POST', json_data=body)
    if not res:
        raise Exception('Could not find alert.')
    return CommandResults(readable_output='Alert was updated successfully.')


def alert_search_command(client: Client, status: str = None, username: str = None, feedname: str = None,
                         hostname: str = None, report: str = None, sort: str = None, query: str = None,
                         facet: str = None, rows: str = None, start: str = None):
    res = client.get_alerts(status, username, feedname, hostname, report, sort, query, facet, rows, start)
    if not res:
        raise Exception('Request cannot be processed.')

    result_section = res.get('results', [])
    facet_section = res.get('facets', {})

    outputs = {
        'Results': result_section,
        'Facets': facet_section
    }
    # TODO return


def binary_summary_command(client: Client, md5: str) -> CommandResults:
    url = f'/v1/binary/{md5}/summary'
    res = client.http_request(url=url, method='GET')
    if not res:
        return CommandResults(
            readable_output=f'Could not find data for file {md5}.')
    return CommandResults(outputs=res, outputs_prefix='CBBinarySummery', outputs_key_field='md5',
                          readable_output=tableToMarkdown(f'Summary For File {md5}', res))


def binary_download_command(client: Client, md5: str) -> CommandResults:
    url = f'/v1/binary/{md5}'
    try:
        res = client.http_request(url=url, method='GET', ok_codes=(200, 204, 404))
        if not res:
            return CommandResults(
                readable_output=f'Could not find data for file {md5}.')
        # todo: add file to command results
        return CommandResults()

    except DemistoException as e:
        if '404' in e.message:
            return CommandResults(readable_output=f'File {md5} could not be found')
        else:
            raise Exception(f'Error connecting to API. Error: {e.message}')


def binary_search_command(client: Client, md5: str = None, product_name: str = None, digital_signature: str = None,
                          group: str = None, hostname: str = None, publisher: str = None, company_name: str = None,
                          sort: str = None, observed_filename: str = None, query: str = None, facet: str = None,
                          facet_field: str = None, rows: str = None, start: str = None) -> CommandResults:
    res = client.get_binaries(md5, product_name, digital_signature, group, hostname, publisher, company_name, sort,
                              observed_filename, query, facet, facet_field, rows, start)

    if not res:
        raise Exception('Request cannot be processed.')

    result_section = res.get('results', [])
    facet_results = res.get('facets', {})
    if facet:
        facet_results = facet_results.get(facet_field)

    return [
        CommandResults(outputs=result_section, outputs_prefix='CBBinarySearch', outputs_key_field='md5',
                       readable_output=result_section),
        CommandResults(outputs=facet_results, outputs_prefix='CBBinarySearchFacet', outputs_key_field='name',
                       readable_output=facet_results)
    ]


def process_segments_get_command(client: Client, process_id: str) -> CommandResults:
    url = f'/v1/process/{process_id}/segment'
    res = client.http_request(url=url, method='GET')
    if not res:
        return CommandResults(
            readable_output=f'Could not find segment data for process id {process_id}.')

    return CommandResults(outputs=res, outputs_prefix='CBProcessSegment', outputs_key_field='unique_id',
                          readable_output=res)


def process_get_command(client: Client, process_id: str, segment_id: str, get_related: bool = False) -> CommandResults:
    url = f"/{'v1' if get_related else 'v2'}/process/{process_id}/{segment_id}"
    res = client.http_request(url=url, method='GET')
    if not res:
        return CommandResults(
            readable_output=f'Could not find result for process id {process_id} with segment id {segment_id}.')

    return CommandResults(outputs=res, outputs_prefix='CBProcessGet', outputs_key_field='id',
                          readable_output=res)


def processes_search_command(client: Client, process_name: str = None, group: str = None, hostname: str = None,
                             parent_name: str = None, process_path: str = None, md5: str = None,
                             query: str = None, group_by: str = None, sort: str = None, facet: str = None,
                             facet_field: str = None, rows: str = None, start: str = None):
    res = client.get_processes(process_name, group, hostname, parent_name, process_path, md5, query, group_by, sort,
                               facet, facet_field, rows, start)

    if not res:
        raise Exception('Request cannot be processed.')

    result_section = res.get('results', [])
    facet_results = res.get('facets', {})

    return [
        CommandResults(outputs=result_section, outputs_prefix='CBProcessSearch', outputs_key_field='id',
                       readable_output=result_section),
        CommandResults(outputs=facet_results, outputs_prefix='CBProcessSearchFacet', outputs_key_field='id',
                       readable_output=facet_results)
    ]


def sensor_installer_download_command(client: Client, os_type: str, group_id: str):
    url = f"/v1/group/{group_id}/installer/{os_type.replace('_', '/')}"
    res = client.http_request(url=url, method='GET')
    if not res:
        return CommandResults(
            readable_output=f'Could not find installer for group id {group_id} which compatible with {os_type}.')
    # todo return file


def endpoint_command(client: Client, id: str, ip: str, hostname: str):
    if not id or not ip or not hostname:
        raise Exception('In order to run this command, please provide valid id, ip and hostname')

    res = client.get_sensors(id=id, ipaddr=ip, hostname=hostname)
    endpoints = []
    command_results = []
    for sensor in res:
        is_isolated = _get_isolation_status_field(sensor.get('network_isolation_enabled'), sensor.get('is_isolating'))
        endpoint = Common.Endpoint(
            id=id,
            hostname=hostname,
            ip_address=ip,
            mac_address=_parse_field(sensor.get('network_adapters', ''), index_after_split=1, chars_to_remove='|'),
            os_version=sensor.get('os_environment_display_string'),
            memory=sensor.get('physical_memory_size'),
            status='Online' if sensor.get('status') else 'Offline',
            is_isolated=is_isolated,
            vendor='Carbon Black Response')
        endpoints.append(endpoint)

        endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
        md = tableToMarkdown(f'Carbon Black Response Endpoint: {id}', endpoint_context)

        command_results.append(CommandResults(
            readable_output=md,
            raw_response=res,
            indicator=endpoint
        ))
    return command_results


def test_module(client: Client) -> str:
    message: str = ''
    try:

        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_token = demisto.params().get('apitoken')
    base_url = urljoin(demisto.params()['url'], '/api')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    command = demisto.command()
    args = demisto.args() if demisto.args() else {}
    demisto.debug(f'Command being called is {command}')
    try:

        client = Client(
            base_url=base_url,
            use_ssl=verify_certificate,
            use_proxy=proxy,
            apitoken=api_token
        )
        commands: Dict[str, Callable] = {'cb-edr-processes-search': processes_search_command,
                                         'cb-edr-process-get': process_get_command,
                                         'cb-edr-process-segments-get': process_segments_get_command,
                                         'cb-edr-process-events-list': '',
                                         'cb-edr-binary-search': binary_search_command,
                                         'cb-edr-binary-download': binary_download_command,
                                         'cb-edr-binary-summary': binary_summary_command,
                                         'cb-edr-alert-search': alert_search_command,
                                         'cb-edr-alert-update': alert_update_command,
                                         'cb-edr-binary-bans-list': binary_bans_list_command,
                                         'cb-edr-binary-ban': binary_ban_command,
                                         'cb-edr-watchlists-list': get_watchlist_list_command,
                                         'cb-edr-watchlist-create': watchlist_create_command,
                                         'cb-edr-watchlist-update': watchlist_update_command,
                                         'cb-edr-watchlist-delete': watchlist_delete_command,
                                         'cb-edr-sensors-list': sensors_list_command,
                                         'cb-edr-quarantine-device': quarantine_device_command,
                                         'cb-edr-unquarantine-device': unquarantine_device_command,
                                         'cb-edr-sensor-installer-download': sensor_installer_download_command,
                                         'fetch-incidents': '',
                                         'endpoint': endpoint_command
                                         }

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'fetch-incidents':
            return
            # return_results(baseintegration_dummy_command(client, demisto.args()))
        elif command in commands:
            return_results(commands[command](client, **args))
        else:
            raise NotImplementedError(f'command {command} was not implemented in this integration.')
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
