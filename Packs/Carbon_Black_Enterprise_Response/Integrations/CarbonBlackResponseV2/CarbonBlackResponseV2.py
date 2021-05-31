import dateparser
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *  # noqa
from typing import Callable, Dict, List, Any, Union

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
INTEGRATION_NAME = 'Carbon Black EDR'
MAX_INCIDENTS_TO_FETCH = 10

''' PARSING PROCESS EVENT COMPLEX FIELDS CLASS'''


class ProcessEventDetail:

    def __init__(self, piped_version: Union[str,list], fields):
        self.fields = []
        if not isinstance(piped_version, list):
            piped_version = [piped_version]
        for entry in piped_version:
            data = entry.split('|')
            if len(data) != len(fields):
                demisto.debug(f'{INTEGRATION_NAME} - Missing details. Ignoring entry: {entry}.')
            self.fields.append(dict(zip(fields, data)))

    def format(self):
        return self.fields

    def set_field_value(self, key, new_val):
        self.fields[key] = new_val

class filemod_complete(ProcessEventDetail):
    FIELDS = ['operation_type', 'event_time', 'file_path', 'md5_after_last_write',
              'file_type', 'flagged_as_potential_tamper_attempt']
    OPERATION_TYPE = {'1': 'Created the file',
                      '2': 'First wrote to the file',
                      '4': 'Deleted the file',
                      '8': 'Last wrote to the file'}
    FILE_TYPE = {'1': 'PE',
                 '2': 'Elf',
                 '3': 'UniversalBin',
                 '8': 'EICAR',
                 '16': 'OfficeLegacy',
                 '17': 'OfficeOpenXml',
                 '48': 'Pdf',
                 '64': 'ArchivePkzip',
                 '65': 'ArchiveLzh',
                 '66': 'ArchiveLzw',
                 '67': 'ArchiveRar',
                 '68': 'ArchiveTar',
                 '69': 'Archive7zip'}

    def __init__(self, piped_version):
        super().__init__(piped_version, self.FIELDS)

    def format(self):
        for entry in self.fields:
            entry['operation_type'] = self.OPERATION_TYPE.get(entry.get('operation_type', ''), '')
            entry['file_type'] = self.FILE_TYPE.get(entry.get('file_type', ''), '')
        return self.fields


class modload_complete(ProcessEventDetail):
    FIELDS = ['event_time', 'loaded_module_md5', 'loaded_module_full_path']

    def __init__(self, piped_version):
        super().__init__(piped_version, self.FIELDS)

    def format(self):
        return self.fields


class regmod_complete(ProcessEventDetail):
    FIELDS = ['operation_type', 'event_time', 'registry_key_path']
    OPERATION_TYPE = {'1': 'Created the file',
                      '2': 'First wrote to the file',
                      '4': 'Deleted the file',
                      '8': 'Last wrote to the file'}

    def __init__(self, piped_version):
        super().__init__(piped_version, self.FIELDS)

    def format(self):
        for entry in self.fields:
            entry['operation_type'] = self.OPERATION_TYPE.get(entry.get('operation_type', ''), '')
        return self.fields


class crossproc_complete(ProcessEventDetail):
    FIELDS = ['cross-process_access_type', 'event_time', 'targeted_process_unique_id',
              'targeted_process_md5', 'targeted_process_path', 'ProcessOpen_sub-type',
              'requested_access_priviledges', 'flagged_as_potential_tamper_attempt']
    SUB_TYPES = {'1': 'handle open to process', '2': 'handle open to thread in process'}

    def __init__(self, piped_version):
        super().__init__(piped_version, self.FIELDS)

    def format(self):
        for entry in self.fields:
            entry['ProcessOpen_sub-type'] = self.SUB_TYPES.get(entry.get('ProcessOpen_sub-type', ''), '')
        return self.fields


''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, apitoken: str, use_ssl: bool, use_proxy: bool):
        headers = {'X-Auth-Token': apitoken, 'Accept': 'application/json', 'Content-Type': 'application/json'}
        super().__init__(base_url, headers=headers, verify=use_ssl, proxy=use_proxy)

    def http_request(self, url: str, method: str, params: dict = None, json_data: dict = None,
                     ok_codes: tuple = (200, 204), resp_type: str = 'json') -> dict:
        """
        initiates a http request to openphish
        """
        data = self._http_request(
            method=method,
            ok_codes=ok_codes,
            url_suffix=url,
            params=params,
            resp_type=resp_type,
            return_empty_response=True,
            json_data=json_data,
            timeout=30,
        )
        return data

    def get_sensors(self, id: str = None, hostname: str = None, ipaddr: str = None,  # noqa: F841
                    groupid: str = None, inactive_filter_days: str = None,  # noqa: F841
                    limit: Union[int, str] = None) -> List[dict]:
        url = f'/v1/sensor/{id}' if id else '/v1/sensor'
        query_fields = ['ipaddr', 'hostname', 'groupid', 'inactive_filter_days']
        query_params: dict = {key: locals().get(key) for key in query_fields if
                              locals().get(key)}
        res = self.http_request(url=url, method='GET', params=query_params, ok_codes=(200, 204))

        # When querying specific sensor without filters, the api returns dictionary instead of list.
        return res[:arg_to_number(limit, 'limit')] if isinstance(res, list) else [res]

    def get_alerts(self, status: str = None, username: str = None, feedname: str = None,
                   hostname: str = None, report: str = None, sort: str = None, query: str = None,
                   facet: str = None, limit: Union[str, int] = None, start: str = None) -> dict:

        query_fields = ['status', 'username', 'feedname', 'hostname', 'report', 'query']
        local_params = locals()
        query_params = {key: local_params.get(key) for key in query_fields if local_params.get(key)}
        query_string = _create_query_string(query_params)
        params = assign_params(q=query_string,
                               rows=arg_to_number(limit, 'limit'),
                               start=start,
                               sort=sort,
                               facet=facet,
                               )

        return self.http_request(url='/v2/alert', method='GET', params=params)

    def get_binaries(self, md5: str = None, product_name: str = None, signed: str = None,  # noqa: F841
                     group: str = None, hostname: str = None, digsig_publisher: str = None,   # noqa: F841
                     company_name: str = None, sort: str = None,
                     observed_filename: str = None, query: str = None, facet: str = None,
                     limit: str = None, start: str = None) -> dict:
        query_fields = ['md5', 'product_name', 'signed', 'group', 'hostname', 'digsig_publisher', 'company_name',
                        'observed_filename', 'query']
        local_params = locals()
        query_params = {key: local_params.get(key) for key in query_fields if local_params.get(key)}
        query_string = _create_query_string(query_params)
        params = assign_params(q=query_string,
                               rows=arg_to_number(limit, 'limit'),
                               start=start,
                               sort=sort,
                               facet=facet,
                               )
        return self.http_request(url='/v1/binary', method='GET', params=params)

    def get_processes(self, process_name: str = None, group: str = None, hostname: str = None,
                      parent_name: str = None, process_path: str = None, md5: str = None,
                      query: str = None, group_by: str = None, sort: str = None, facet: str = None,
                      facet_field: str = None, limit: str = None, start: str = None):
        query_fields = ['process_name', 'group', 'hostname', 'parent_name', 'process_path', 'md5', 'query']
        local_params = locals()
        query_params = {key: local_params.get(key) for key in query_fields if local_params.get(key)}
        query_string = _create_query_string(query_params)
        params = assign_params(q=query_string,
                               rows=arg_to_number(limit, 'limit'),
                               start=start,
                               sort=sort,
                               facet=facet,
                               )
        if facet_field:
            params['facet.field'] = facet_field
        if group_by:
            params['cb.group'] = group_by
        return self.http_request(url='/v1/process', method='GET', params=params)

    def get_formatted_ProcessEventDetail(self, process_json: dict):
        COMPLEX_FIELDS = {'filemod_complete': filemod_complete, 'modload_complete': modload_complete,
                          'regmod_complete': regmod_complete, 'crossproc_complete': crossproc_complete}
        formatted_json = {}
        for field in process_json:
            if field in COMPLEX_FIELDS:
                field_object: ProcessEventDetail = COMPLEX_FIELDS[field](process_json.get(field))
                formatted_json[field] = field_object.format()
            else:
                formatted_json[field] = process_json.get(field)

        return formatted_json


''' HELPER FUNCTIONS '''


def _create_query_string(params: dict) -> str:
    if 'query' in params:
        return params['query']
    current_query = [f"{query_field}:{params[query_field]}" for query_field in params]
    current_query = ' AND '.join(current_query)

    if not current_query:
        raise Exception(f'{INTEGRATION_NAME} - Search without any filter is not permitted.')

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
        raise Exception(f'{INTEGRATION_NAME} - could not un-isolate sensor {sensor_id}')
    return CommandResults(readable_output='Sensor was un-isolated successfully.')


def quarantine_device_command(client: Client, sensor_id: str) -> CommandResults:
    url = f'/v1/sensor/{sensor_id}'
    res = client.http_request(url=url, method='PUT',
                              json_data=_get_sensor_isolation_change_body(client, sensor_id, True))
    if not res:
        raise Exception(f'{INTEGRATION_NAME} - could not isolate sensor {sensor_id}')
    return CommandResults(readable_output='Sensor was isolated successfully.')


def sensors_list_command(client: Client, id: str = None, hostname: str = None, ip: str = None,
                         group_id: str = None, inactive_filter_days: str = None, limit: int = None) -> CommandResults:
    try:
        res = client.get_sensors(id, hostname, ip, group_id, inactive_filter_days, limit)

        res = res[:limit]

        human_readable_data = []
        for sensor_data in res:
            human_readable_data.append({
                'Computer Name': sensor_data.get('computer_name'),
                'Status': sensor_data.get('status'),
                'OS Version': sensor_data.get('os_type'),
                'Node Id': sensor_data.get('node_id'),
                'Sensor Version': sensor_data.get('build_version_string'),
                'Sensor Id': sensor_data.get('id'),
                'IP Address/MAC Info': _parse_field(sensor_data.get('network_adapters', ''), index_after_split=1,
                                                    chars_to_remove='|'),
                'Group ID': sensor_data.get('group_id'),
                'Power State': sensor_data.get('power_state'),
                'Health Score': sensor_data.get('sensor_health_status'),
                'Is Isolating': sensor_data.get('is_isolating')

            })
        return CommandResults(outputs=res, outputs_prefix='CarbonBlackEDR.Sensor', outputs_key_field='id',
                              readable_output=tableToMarkdown(f'{INTEGRATION_NAME} - Sensors', human_readable_data,
                                                              removeNull=True),
                              raw_response=res)
    except DemistoException as e:
        if '404' in e.message:
            raise Exception(f'{INTEGRATION_NAME} - The sensor {id} could not be found. '
                            f'Please try using a different sensor.')
        else:
            raise Exception(f'{INTEGRATION_NAME} - Error connecting to API. Error: {e.message}')


def watchlist_delete_command(client: Client, id: str) -> CommandResults:
    res = client.http_request(url=f'/v1/watchlist/{id}', method='DELETE')
    # res contains whether the task successful.
    return CommandResults(readable_output=res.get('result'))


def watchlist_update_command(client: Client, id: str, search_query: str, description: str,
                             enabled: bool) -> CommandResults:
    params = assign_params(enabled=enabled, search_query=search_query, description=description)
    res = client.http_request(url=f'/v1/watchlist/{id}', method='PUT', json_data=params)

    # res contains whether the task successful.
    return CommandResults(readable_output=res.get('result'))


def watchlist_create_command(client: Client, name: str, search_query: str, index_type: str = 'events',
                             description: str = '') -> CommandResults:
    params = assign_params(name=name, search_query=search_query, description=description, index_type=index_type)
    res = client.http_request(url='/v1/watchlist', method='POST', json_data=params)
    id = res.get('id')
    if id:
        return CommandResults(outputs=res, outputs_prefix='CarbonBlackEDR.Watchlist', outputs_key_field='id',
                              readable_output=f"Successfully created new watchlist with id {id}")
    return CommandResults(readable_output="Could not create new watchlist.")


def get_watchlist_list_command(client: Client, id: str = None, limit: str = None) -> CommandResults:
    url = f'/v1/watchlist/{id}' if id else '/v1/watchlist'
    res: Union[dict, list] = client.http_request(url=url, method='GET')

    human_readable_data = []
    # Handling case of only one record.
    if id:
        res = [res]
    res = res[:arg_to_number(limit, 'limit')]
    for watchlist in res:
        human_readable_data.append({
            'Name': watchlist.get('name'),
            'ID': watchlist.get('id'),
            'Group ID': watchlist.get('group_id'),
            'Description': watchlist.get('description'),
            'Total Hits': watchlist.get('total_hits'),
            'Query': watchlist.get('search_query'),
        })

    md = tableToMarkdown(f'{INTEGRATION_NAME} - Watchlists', human_readable_data, removeNull=True)
    md += f"\nShowing {len(res.get('results'))} out of {res.get('total_results')} results."

    return CommandResults(outputs=res, outputs_prefix='CarbonBlackEDR.Watchlist', outputs_key_field='name',
                          readable_output=md)


def binary_ban_command(client: Client, md5: str, text: str, last_ban_time: str = None, ban_count: str = None,
                       last_ban_host: str = None,
                       enabled: bool = None) -> CommandResults:
    body = assign_params(md5hash=md5,
                         text=text, last_ban_time=last_ban_time, ban_count=ban_count,
                         last_ban_host=last_ban_host, enabled=enabled)
    try:
        client.http_request(url='/v1/banning/blacklist', method='POST', json_data=body)
    except DemistoException as e:
        if '409' in e.message:
            return CommandResults(readable_output=f'Ban for md5 {md5} already exists')
        else:
            raise Exception(f'{INTEGRATION_NAME} - Error connecting to API. Error: {e.message}')
    return CommandResults(readable_output='hash banned successfully')


def binary_bans_list_command(client: Client) -> CommandResults:
    res = client.http_request(url='/v1/banning/blacklist', method='GET')
    human_readable_data = []
    for banned in res:
        human_readable_data.append({
            'md5': banned.get('md5hash'),
            'Text': banned.get('text'),
            'Timestamp': banned.get('timestamp'),
            'User ID': banned.get('user_id'),
            'Username': banned.get('username'),
        })

    return CommandResults(outputs=res, outputs_prefix='CarbonBlackEDR.BinaryBan', outputs_key_field='md5',
                          readable_output=tableToMarkdown(f'{INTEGRATION_NAME} -Banned Hashes', human_readable_data))


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
        raise Exception(f"{INTEGRATION_NAME} - Could not find alerts: {', '.join(alert_ids)}.")
    return CommandResults(readable_output='Alert was updated successfully.')


def alert_search_command(client: Client, status: str = None, username: str = None, feedname: str = None,
                         hostname: str = None, report: str = None, sort: str = None, query: str = None,
                         facet: str = None, limit: str = None, start: str = None) -> CommandResults:
    res = client.get_alerts(status, username, feedname, hostname, report, sort, query, facet, limit, start)
    if not res:
        raise Exception(f'{INTEGRATION_NAME} - Request cannot be processed.')

    alerts = res.get('results', [])
    human_readable_data = []
    for alert in alerts:
        human_readable_data.append({
            'File Name': alert.get('process_name'),
            'File Path': alert.get('process_path'),
            'Hostname': alert.get('hostname'),
            'Source md5': alert.get('md5'),
            'Segment ID': alert.get('segment_id'),
            'Severity': alert.get('alert_severity'),
            'Created Time': alert.get('created_time'),
            'Status': alert.get('status'),
        })

    outputs = assign_params(Results=alerts, Facets=res.get('facets'))

    md = tableToMarkdown(f'{INTEGRATION_NAME} - Alert Search Results', human_readable_data)
    md += f"\nShowing {len(res.get('results'))} out of {res.get('total_results')} results."

    return CommandResults(outputs=outputs, outputs_prefix='CarbonBlackEDR.Alert',
                          outputs_key_field='unique_id',
                          readable_output=md)


def binary_summary_command(client: Client, md5: str) -> CommandResults:
    url = f'/v1/binary/{md5}/summary'
    res = client.http_request(url=url, method='GET')
    if not res:
        return CommandResults(
            readable_output=f'Could not find data for file {md5}.')

    human_readable_data = {
        'Host Count': res.get('host_count'),
        'Group': res.get('group'),
        'OS Type': res.get('os_type'),
        'Timestamp': res.get('timestamp'),
        'md5': res.get('md5'),
        'Last Seen': res.get('last_seen'),
        'Is Executable Image': res.get('is_executable_image')
    }

    return CommandResults(outputs=res, outputs_prefix='CarbonBlackEDR.BinaryMetadata', outputs_key_field='md5',
                          readable_output=tableToMarkdown(f'{INTEGRATION_NAME} -Summary For File {md5}',
                                                          human_readable_data,
                                                          removeNull=True))


def binary_download_command(client: Client, md5: str) -> CommandResults:
    url = f'/v1/binary/{md5}'
    try:
        res = client.http_request(url=url, method='GET', ok_codes=(200, 204, 404), resp_type='content')
        if not res:
            return CommandResults(
                readable_output=f'Could not find data for file {md5}.')
        return fileResult(f'binary_{md5}.zip', res, file_type=9)

    except DemistoException as e:
        if '404' in e.message:
            return CommandResults(readable_output=f'File {md5} could not be found')
        else:
            raise Exception(f'{INTEGRATION_NAME} - Error connecting to API. Error: {e.message}')


def binary_search_command(client: Client, md5: str = None, product_name: str = None, digital_signature: str = None,
                          group: str = None, hostname: str = None, publisher: str = None, company_name: str = None,
                          sort: str = None, observed_filename: str = None, query: str = None, facet: str = None,
                          limit: str = '50', start: str = None) -> CommandResults:
    res = client.get_binaries(md5, product_name, digital_signature, group, hostname, publisher, company_name, sort,
                              observed_filename, query, facet, limit, start)

    if not res:
        raise Exception(f'{INTEGRATION_NAME} - Request cannot be processed.')

    outputs = assign_params(Results=res.get('results'), Facets=res.get('facets'))
    human_readable_data = []
    for binary_file in res.get('results', []):
        human_readable_data.append({
            'Host Count': binary_file.get('host_count'),
            'Group': binary_file.get('group'),
            'OS Type': binary_file.get('os_type'),
            'Timestamp': binary_file.get('timestamp'),
            'md5': binary_file.get('md5'),
            'Last Seen': binary_file.get('last_seen'),
            'Is Executable Image': binary_file.get('is_executable_image')
        })

    md = tableToMarkdown(f'{INTEGRATION_NAME} - Binary Search Results', human_readable_data)
    md += f"\nShowing {len(res.get('results'))} out of {res.get('total_results')} results."

    return CommandResults(outputs=outputs, outputs_prefix='CarbonBlackEDR.BinarySearch',
                          outputs_key_field='md5',
                          readable_output=md)


def process_events_list_command(client: Client, process_id: str, segment_id: str, start: str = None, count: str = None):
    if not process_id or not segment_id:
        raise Exception(f'{INTEGRATION_NAME} - Please provide both process id and segment id to run this command.')
    url = f'/v3/process/{process_id}/{segment_id}/event'
    start = int(start) if start else None
    count = int(count) if count else None
    params = {}
    if start:
        params['cb.event_start'] = start
    if count:
        params['cb.event_count'] = count
    res = client.http_request(url=url, method='GET', params=params)
    process = client.get_formatted_ProcessEventDetail(res.get('process', {}))

    return CommandResults(outputs=process, outputs_prefix='CarbonBlackEDR.Events',
                          outputs_key_field='id',
                          readable_output=process, raw_response=res)


def process_segments_get_command(client: Client, process_id: str) -> CommandResults:
    url = f'/v1/process/{process_id}/segment'
    res = client.http_request(url=url, method='GET')
    if not res:
        return CommandResults(
            readable_output=f'Could not find segment data for process id {process_id}.')

    # Human readable is depending on request therefore is not prettified.
    return CommandResults(outputs=res.get('process'), outputs_prefix='CarbonBlackEDR.ProcessSegments',
                          outputs_key_field='unique_id',
                          readable_output=res.get('process', {}).get('segments'))


def process_get_command(client: Client, process_id: str, segment_id: str,
                        get_related: bool = False) -> CommandResults:
    get_related = argToBoolean(get_related)
    url = f"/{'v1' if get_related else 'v2'}/process/{process_id}/{segment_id}"
    try:
        res = client.http_request(url=url, method='GET')
    except DemistoException as e:
        if "404" in e.message:
            raise Exception(f'{INTEGRATION_NAME} - Could not find result for '
                            f'process id {process_id} with segment id {segment_id}.')
        else:
            raise Exception(f'{INTEGRATION_NAME} - Error connecting to API. Error: {e.message}')

    data = res.get('process', {}) if get_related else res
    human_readable_data = {
        'Process Path': data.get('path'),
        'Process md5': data.get('process_md5'),
        'Process Name': data.get('process_name'),
        'Process PID': data.get('process_pid'),
        'Process ID': data.get('id'),
        'Hostname': data.get('hostname'),
        'Segment ID': data.get('segment_id'),
        'Username': data.get('username'),
        'Last Update': data.get('last_update'),
        'Is Terminated': data.get('terminated')
    }

    return CommandResults(outputs=res, outputs_prefix='CarbonBlackEDR.Process', outputs_key_field='id',
                          readable_output=tableToMarkdown(f'{INTEGRATION_NAME} - Process', human_readable_data))


def processes_search_command(client: Client, process_name: str = None, group: str = None, hostname: str = None,
                             parent_name: str = None, process_path: str = None, md5: str = None,
                             query: str = None, group_by: str = None, sort: str = None, facet: str = None,
                             facet_field: str = None, limit: str = '50', start: str = None):
    res = client.get_processes(process_name, group, hostname, parent_name, process_path, md5, query, group_by, sort,
                               facet, facet_field, limit, start)

    if not res:
        raise Exception(f'{INTEGRATION_NAME} - Request cannot be processed.')

    outputs = assign_params(Results=res.get('results'), Facets=res.get('facets'))

    human_readable_data = []
    for process in res.get('results'):
        human_readable_data.append(
            {
                'Process Path': process.get('path'),
                'Process md5': process.get('process_md5'),
                'Process Name': process.get('process_name'),
                'Process PID': process.get('process_pid'),
                'Process ID': process.get('id'),
                'Hostname': process.get('hostname'),
                'Segment ID': process.get('segment_id'),
                'Username': process.get('username'),
                'Last Update': process.get('last_update'),
                'Is Terminated': process.get('terminated')
            })
    md = tableToMarkdown(f'{INTEGRATION_NAME} - Process Search Results', human_readable_data, removeNull=True)
    md += f"\nShowing {len(res.get('results'))} out of {res.get('total_results')} results."

    return CommandResults(outputs=outputs, outputs_prefix='CarbonBlackEDR.Process', outputs_key_field='id',
                          readable_output=md)


def sensor_installer_download_command(client: Client, os_type: str, group_id: str):
    url = f"/v1/group/{group_id}/installer/{os_type.replace('_', '/')}"
    res = client.http_request(url=url, method='GET', resp_type='content')
    if not res:
        return CommandResults(
            readable_output=f'Could not find installer for group id {group_id} which compatible with {os_type}.')
    return fileResult(f'sensor_installer_{group_id}_{os_type}.zip', res, file_type=9)


def endpoint_command(client: Client, id: str, ip: str, hostname: str):
    if not id and not ip and not hostname:
        raise Exception(f'{INTEGRATION_NAME} - In order to run this command, please provide valid id, ip or hostname')

    try:
        res = client.get_sensors(id=id, ipaddr=ip, hostname=hostname)
        endpoints = []
        command_results = []
        for sensor in res:
            is_isolated = _get_isolation_status_field(sensor['network_isolation_enabled'],
                                                      sensor['is_isolating'])
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
            md = tableToMarkdown(f'{INTEGRATION_NAME} -  Endpoint: {id}', endpoint_context)

            command_results.append(CommandResults(
                readable_output=md,
                raw_response=res,
                indicator=endpoint
            ))
        return command_results
    except Exception:
        return CommandResults(readable_output=f'{INTEGRATION_NAME} - Could not get endpoint')


def fetch_incidents(client: Client, max_results: int, last_run: dict, first_fetch_time: int, status: str,
                    feedname: str, hostname: str, query: str):
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch time
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = last_fetch

    incidents: List[Dict[str, Any]] = []
    res = client.get_alerts(status=status, feedname=feedname, hostname=hostname, query=query, limit=max_results)
    alerts = res.get('results', {})

    for alert in alerts:
        incident_created_time = dateparser.parse(alert.get('created_time'))
        incident_created_time_ms = int(incident_created_time.timestamp()) * 1000 if incident_created_time else '0'

        # to prevent duplicates, adding incidents with creation_time > last fetched incident
        if last_fetch:
            if incident_created_time_ms <= last_fetch:
                continue

        # If no name is present it will throw an exception
        incident_name = alert['process_name']

        incident = {
            'name': incident_name,
            # 'details': alert['name'],
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(alert),
            # 'type': 'Hello World Alert',  # Map to a specific XSOAR incident Type
            # 'severity': convert_to_demisto_severity(alert.get('alert_severity', 'Low')),
            # 'CustomFields': {  # Map specific XSOAR Custom Fields
            #     'helloworldid': alert.get('alert_id'),
            #     'helloworldstatus': alert.get('alert_status'),
            #     'helloworldtype': alert.get('alert_type')
            # }
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time_ms > latest_created_time:
            latest_created_time = incident_created_time_ms

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


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
    try:
        api_token = demisto.params().get('apitoken')
        base_url = urljoin(demisto.params()['url'], '/api')
        verify_certificate = not demisto.params().get('insecure', False)
        proxy = demisto.params().get('proxy', False)
        command = demisto.command()
        args = demisto.args() if demisto.args() else {}
        demisto.debug(f'Command being called is {command}')

        client = Client(
            base_url=base_url,
            use_ssl=verify_certificate,
            use_proxy=proxy,
            apitoken=api_token
        )
        commands: Dict[str, Callable] = {'cb-edr-processes-search': processes_search_command,
                                         'cb-edr-process-get': process_get_command,
                                         'cb-edr-process-segments-get': process_segments_get_command,
                                         'cb-edr-process-events-list': process_events_list_command,
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
                                         'fetch-incidents': fetch_incidents,
                                         'endpoint': endpoint_command
                                         }

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = demisto.params().get('alert_status', None)
            alert_feed_name = demisto.params().get('alert_feed_name', None)
            alert_hostname = demisto.params().get('alert_hostname', None)
            alert_query = demisto.params().get('alert_query', None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH
            # How much time before the first fetch to retrieve incidents
            first_fetch_time = arg_to_datetime(
                arg=demisto.params().get('first_fetch', '3 days'),
                arg_name='First fetch time',
                required=True
            )
            first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
            # Using assert as a type guard (since first_fetch_time is always an int when required=True)
            assert isinstance(first_fetch_timestamp, int)

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                status=alert_status,
                feedname=alert_feed_name,
                hostname=alert_hostname,
                query=alert_query)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

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
