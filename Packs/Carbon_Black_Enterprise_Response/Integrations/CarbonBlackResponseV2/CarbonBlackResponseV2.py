import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import struct
import dateparser
import urllib3
from CommonServerUserPython import *  # noqa
from typing import Any
from collections.abc import Callable

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
INTEGRATION_NAME = 'Carbon Black EDR'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' PARSING PROCESS EVENT COMPLEX FIELDS CLASS'''


class ProcessEventDetail:
    """
    This class representing the Process Event Details as found here:
    https://developer.carbonblack.com/reference/enterprise-response/6.3/rest-api/#process-event-details
    Each sub-class representing a different piped-versioned field, and support the format method.
    """

    def __init__(self, piped_version: str | list, fields):
        self.fields = []
        if not isinstance(piped_version, list):
            piped_version = [piped_version]
        for entry in piped_version:
            data = entry.split('|')

            # zip works when number of values is not equal, which can result in incorrect data.
            if len(data) != len(fields):
                demisto.debug(f'{INTEGRATION_NAME} - Missing details. Ignoring entry: {entry}.')

            self.fields.append(dict(zip(fields, data)))

    def format(self):
        return self.fields


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


class netconn_complete(ProcessEventDetail):
    """
    For netconn_complete, the v2 API and newer return an array of JSON objects instead of piped-versioned fields.
    https://developer.carbonblack.com/reference/enterprise-response/5.1/rest-api/#netconn_complete
    """

    def __init__(self, fields):
        self.fields = fields

    def format(self):
        for entry in self.fields:
            for ipfield in ("remote_ip", "local_ip"):
                if isinstance(entry[ipfield], int):
                    entry[ipfield] = socket.inet_ntoa(struct.pack('>i', entry[ipfield]))
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
                    limit: int | str | None = None) -> tuple[int, list[dict]]:
        url = f'/v1/sensor/{id}' if id else '/v1/sensor'
        query_params = assign_params(
            ip=ipaddr,
            hostname=hostname,
            groupid=groupid,
            inactive_filter_days=inactive_filter_days
        )
        res = self.http_request(url=url, method='GET', params=query_params, ok_codes=(200, 204))

        # When querying specific sensor without filters, the api returns dictionary instead of list.
        return len(res), res[:arg_to_number(limit, 'limit')] if isinstance(res, list) else [res]

    def get_alerts(self, status: str | None = None, username: str | None = None, feedname: str | None = None,
                   hostname: str | None = None, report: str | None = None, sort: str | None = None, query: str | None = None,
                   facet: str | None = None, limit: str | int | None = None, start: str | None = None,
                   allow_empty_params: bool = False) -> dict:

        query_params = assign_params(
            status=status,
            username=username,
            feedname=feedname,
            hostname=hostname,
            report=report,
            query=query
        )
        query_string = _create_query_string(query_params, allow_empty_params=allow_empty_params)
        params = assign_params(q=query_string,
                               rows=arg_to_number(limit, 'limit'),
                               start=start,
                               sort=sort,
                               facet=facet,
                               )

        return self.http_request(url='/v2/alert', method='GET', params=params)

    def get_binaries(self, md5: str = None, product_name: str = None, signed: str = None,  # noqa: F841
                     group: str = None, hostname: str = None, digsig_publisher: str = None,  # noqa: F841
                     company_name: str = None, sort: str = None,
                     observed_filename: str = None, query: str = None, facet: str = None,
                     limit: str = None, start: str = None) -> dict:

        query_params = assign_params(
            md5=md5,
            product_name=product_name,
            signed=signed,
            group=group,
            hostname=hostname,
            digsig_publisher=digsig_publisher,
            company_name=company_name,
            observed_filename=observed_filename,
            query=query
        )
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
                      facet_field: str = None, limit: str = None, start: str = None, allow_empty: bool = False):
        query_fields = ['process_name', 'group', 'hostname', 'parent_name', 'process_path', 'md5', 'query']
        local_params = locals()
        query_params = assign_params(
            process_name=process_name,
            parent_name=parent_name,
            process_path=process_path,
            group=group,
            hostname=hostname,
            md5=md5,
            query=query
        )
        query_string = _create_query_string(query_params, allow_empty)
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
        complex_fields = {'filemod_complete': filemod_complete, 'modload_complete': modload_complete,
                          'regmod_complete': regmod_complete, 'crossproc_complete': crossproc_complete,
                          'netconn_complete': netconn_complete}
        formatted_json = {}
        for field in process_json:
            if field in complex_fields:
                # creating the relevant field object and formatting it.
                field_object: ProcessEventDetail = complex_fields[field](process_json.get(field))
                formatted_json[field] = field_object.format()
            else:
                formatted_json[field] = process_json.get(field)

        return formatted_json


''' HELPER FUNCTIONS '''


def _create_query_string(params: dict, allow_empty_params: bool = False) -> str:
    """
    Creating a cb query from params according to https://developer.carbonblack.com/resources/query_overview.pdf.
    if 'query' in params, it overrides the other params.
    allow_empty_params is used for testing and not production as it would overload the context.
    """
    # If user provided both params and query, it means he is not experienced, and might expect different results,
    # therefore we decided to prohibit the use of both in search commands.
    if 'query' in params and len(params) > 1:
        raise DemistoException(f'{INTEGRATION_NAME} - Searching with both query and other filters is not allowed. '
                               f'Please provide either a search query or one of the possible filters.')
    elif 'query' in params:
        return params['query']

    current_query = [f"{query_field}:{params[query_field]}" for query_field in params]
    current_query = ' AND '.join(current_query)

    if not current_query and not allow_empty_params:
        raise DemistoException(f'{INTEGRATION_NAME} - Search without any filter is not permitted.')

    return current_query


def _add_to_current_query(current_query: str = '', params: dict = None) -> str:
    new_query = ''
    if not params:
        return current_query
    if current_query:
        new_query += f'({current_query}) AND '
    current_query_params = [f"{query_field}:{params[query_field]}" for query_field in params]
    new_query += ' AND '.join(current_query_params)
    return new_query


def _get_sensor_isolation_change_body(client: Client, sensor_id: str, new_isolation: bool) -> dict:
    sensor_data = client.get_sensors(sensor_id)[1][0]  # returns (length, [sensor_data])
    new_sensor_data = {
        'network_isolation_enabled': new_isolation,
        'group_id': sensor_data.get('group_id')
    }

    return new_sensor_data


def _parse_field(raw_field: str, sep: str = ',', index_after_split: int = 0, chars_to_remove: str = '') -> str:
    '''
    This function allows getting a specific complex sub-string. "example,example2|" -> 'example2'
    '''
    if not raw_field:
        demisto.debug(f'{INTEGRATION_NAME} - Got empty raw field to parse.')
        return ''
    try:
        new_field = raw_field.split(sep)[index_after_split]
    except IndexError:
        demisto.error(f'{INTEGRATION_NAME} - raw: {raw_field}, split by {sep} has no index {index_after_split}')
        return ''
    chars_to_remove = set(chars_to_remove)
    for char in chars_to_remove:
        new_field = new_field.replace(char, '')
    return new_field


def _get_isolation_status_field(isolation_activated: bool, is_isolated: bool) -> str:
    # Logic for isolation can be found in:
    # https://developer.carbonblack.com/reference/enterprise-response/6.3/rest-api/#sensorsendpoints
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
        total_num_of_sensors, res = client.get_sensors(
            id, hostname, ip, group_id, inactive_filter_days, limit)  # type: ignore[arg-type]

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

        md = tableToMarkdown(f'{INTEGRATION_NAME} - Sensors', human_readable_data, removeNull=True, headers=[
            'Sensor Id', 'Computer Name', 'Status', 'Power State', 'Group ID', 'OS Version', 'Health Score',
            'Is Isolating', 'Node Id', 'Sensor Version', 'IP Address/MAC Info'])
        md += f"\nShowing {len(res)} out of {total_num_of_sensors} results."
        return CommandResults(outputs=res, outputs_prefix='CarbonBlackEDR.Sensor', outputs_key_field='id',
                              readable_output=md, raw_response=res)
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
                             enabled: bool = None) -> CommandResults:
    params = assign_params(enabled=enabled, search_query=search_query, description=description)
    res = client.http_request(url=f'/v1/watchlist/{id}', method='PUT', json_data=params)

    # res contains whether the task successful.
    return CommandResults(readable_output=res.get('result'))


def watchlist_update_action_command(client: Client, id: str, action_type: str,
                                    enabled: str) -> CommandResults:
    enabled_bool = argToBoolean(enabled)
    params = assign_params(enabled=enabled_bool)
    res = client.http_request(url=f'/v1/watchlist/{id}/action_type/{action_type}', method='PUT', json_data=params)
    # res contains whether the task successful.
    return CommandResults(readable_output=res.get('result'))


def watchlist_create_command(client: Client, name: str, search_query: str, index_type: str = 'events',
                             description: str = '') -> CommandResults:
    params = assign_params(name=name, search_query=search_query, description=description, index_type=index_type)
    res = client.http_request(url='/v1/watchlist', method='POST', json_data=params)
    watchlist_id = res.get('id')
    if watchlist_id:
        output = {'id': watchlist_id}
        return CommandResults(outputs=output, outputs_prefix='CarbonBlackEDR.Watchlist', outputs_key_field='id',
                              readable_output=f"Successfully created new watchlist with id {watchlist_id}")
    return CommandResults(readable_output="Could not create new watchlist.")


def get_watchlist_list_command(client: Client, id: str = None, limit: str = None) -> CommandResults:
    url = f'/v1/watchlist/{id}' if id else '/v1/watchlist'
    res: dict | list = client.http_request(url=url, method='GET')

    human_readable_data = []
    # Handling case of only one record.
    if id:
        res = [res]
    total_num_of_watchlists = len(res)
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

    md = f'{INTEGRATION_NAME} - Watchlists'
    md += tableToMarkdown(f"\nShowing {len(res)} out of {total_num_of_watchlists} results.", human_readable_data,
                          removeNull=True)
    return CommandResults(outputs=res, outputs_prefix='CarbonBlackEDR.Watchlist', outputs_key_field='name',
                          readable_output=md)


def binary_ban_command(client: Client, md5: str, text: str, last_ban_time: str = None, ban_count: str = None,
                       last_ban_host: str = None) -> CommandResults:
    body = assign_params(md5hash=md5,
                         text=text, last_ban_time=last_ban_time, ban_count=ban_count,
                         last_ban_host=last_ban_host)
    try:
        client.http_request(url='/v1/banning/blacklist', method='POST', json_data=body)
    except DemistoException as e:
        if '409' in e.message:
            return CommandResults(readable_output=f'Ban for md5 {md5} already exists')
        else:
            raise Exception(f'{INTEGRATION_NAME} - Error connecting to API. Error: {e.message}')
    return CommandResults(readable_output='hash banned successfully')


def binary_bans_list_command(client: Client, limit: str = None) -> CommandResults:
    res = client.http_request(url='/v1/banning/blacklist', method='GET')
    res = res[:arg_to_number(limit, 'limit')] if limit else res
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
                         facet: str = None, limit: str = None, start: str = '0') -> CommandResults:
    res = client.get_alerts(status, username, feedname, hostname, report, sort,
                            query, facet, limit, start)  # type: ignore[arg-type]
    if not res:
        raise Exception(f'{INTEGRATION_NAME} - Request cannot be processed.')

    alerts = res.get('results', [])
    human_readable_data = []
    for alert in alerts:
        human_readable_data.append({
            'Alert ID': alert.get('unique_id'),
            'File Name': alert.get('process_name'),
            'File Path': alert.get('process_path'),
            'Hostname': alert.get('hostname'),
            'Source md5': alert.get('md5'),
            'Segment ID': alert.get('segment_id'),
            'Severity': alert.get('alert_severity'),
            'Created Time': alert.get('created_time'),
            'Status': alert.get('status'),
        })

    outputs = assign_params(Results=alerts, Facets=res.get('facets'), Terms=res.get('terms'),
                            total_results=res.get('total_results'))

    md = f'{INTEGRATION_NAME} - Alert Search Results'
    md += tableToMarkdown(
        f"\nShowing {start} - {len(res.get('results', []))} out of {res.get('total_results', '0')} results.",
        human_readable_data)

    return CommandResults(outputs=outputs, outputs_prefix='CarbonBlackEDR.Alert',
                          outputs_key_field='Terms',
                          readable_output=md)


def binary_summary_command(client: Client, md5: str) -> CommandResults:
    url = f'/v1/binary/{md5}/summary'
    try:
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
                                                              human_readable_data, removeNull=True))
    except DemistoException as e:
        if '404' in e.message:
            return CommandResults(readable_output=f'File {md5} could not be found')
        else:
            raise Exception(f'{INTEGRATION_NAME} - Error connecting to API. Error: {e.message}')


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
                          limit: str = '50', start: str = '0') -> CommandResults:
    res = client.get_binaries(md5, product_name, digital_signature, group, hostname, publisher, company_name, sort,
                              observed_filename, query, facet, limit, start)

    if not res:
        raise Exception(f'{INTEGRATION_NAME} - Request cannot be processed.')

    outputs = assign_params(Results=res.get('results'), Facets=res.get('facets'), Terms=res.get('terms'),
                            total_results=res.get('total_results'))
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

    md = f'{INTEGRATION_NAME} - Binary Search Results'
    md += tableToMarkdown(f"\nShowing {start} - {len(res.get('results', []))} out of {res.get('total_results', '0')} "
                          f"results.", human_readable_data, headers=['md5', 'Group', 'OS Type', 'Host Count',
                                                                     'Last Seen', 'Is Executable Image', 'Timestamp'])
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


def process_segments_get_command(client: Client, process_id: str, limit: str = '50') -> CommandResults:
    url = f'/v1/process/{process_id}/segment'
    res = client.http_request(url=url, method='GET')
    if not res:
        return CommandResults(
            readable_output=f'Could not find segment data for process id {process_id}.')
    res = res.get('process', {}).get('segments')
    res = res[:arg_to_number(limit, 'limit')] if limit else res
    # Human readable is depending on request therefore is not prettified.
    return CommandResults(outputs=res, outputs_prefix='CarbonBlackEDR.ProcessSegments',
                          outputs_key_field='unique_id',
                          readable_output=res)


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
                             facet_field: str = None, limit: str = '50', start: str = '0'):
    res = client.get_processes(process_name, group, hostname, parent_name, process_path, md5, query, group_by, sort,
                               facet, facet_field, limit, start)

    if not res:
        raise Exception(f'{INTEGRATION_NAME} - Request cannot be processed.')

    outputs = assign_params(Results=res.get('results'), Facets=res.get('facets'), Terms=res.get('terms'),
                            total_results=res.get('total_results'))

    human_readable_data = []
    for process in res.get('results'):
        human_readable_data.append(
            {
                'Process Path': process.get('path'),
                'Process md5': process.get('process_md5'),
                'Process Name': process.get('process_name'),
                'Segment ID': process.get('segment_id'),
                'Process PID': process.get('process_pid'),
                'Process ID': process.get('id'),
                'Hostname': process.get('hostname'),
                'Username': process.get('username'),
                'Last Update': process.get('last_update'),
                'Is Terminated': process.get('terminated')
            })
    md = f'#### {INTEGRATION_NAME} - Process Search Results'
    md += tableToMarkdown(
        f"\nShowing {start} - {len(res.get('results', []))} out of {res.get('total_results', '0')} results.",
        human_readable_data,
        headers=['Process Path', 'Process ID', 'Segment ID', 'Process md5', 'Process Name', 'Hostname',
                 'Process PID', 'Username', 'Last Update', 'Is Terminated'],
        removeNull=True)

    return CommandResults(outputs=outputs, outputs_prefix='CarbonBlackEDR.ProcessSearch', outputs_key_field='Terms',
                          readable_output=md)


def sensor_installer_download_command(client: Client, os_type: str, group_id: str):
    url = f"/v1/group/{group_id}/installer/{os_type.replace('_', '/')}"
    res = client.http_request(url=url, method='GET', resp_type='content')
    if not res:
        return CommandResults(
            readable_output=f'Could not find installer for group id {group_id} which compatible with {os_type}.')
    return fileResult(f'sensor_installer_{group_id}_{os_type}.zip', res, file_type=9)


def endpoint_command(client: Client, id: str = None, ip: str = None, hostname: str = None):
    if not id and not ip and not hostname:
        raise Exception(f'{INTEGRATION_NAME} - In order to run this command, please provide valid id, ip or hostname')

    # If multiple filters were given, we want to retrieve all results that match any filter ('OR', not 'AND')
    # issue https://github.com/demisto/etc/issues/46353. Therefore, we make an API query for every filter separately.
    ips = argToList(ip)
    hostnames = argToList(hostname)
    ids = argToList(id)
    exceptions = []
    res = []
    if ips:
        for current_ip in ips:
            # Carbon Black returns an error in various scenarios (no results matching the query, etc.), wrapping with
            # `try-except` to handle these exceptions here.
            try:
                res += client.get_sensors(ipaddr=current_ip)[1]
            except Exception as e:
                exceptions.append({'Query': f'ip: {current_ip}', 'Exception': str(e)})
    if hostnames:
        for current_hostname in hostnames:
            try:
                res += client.get_sensors(hostname=current_hostname)[1]
            except Exception as e:
                exceptions.append({'Query': f'hostname: {current_hostname}', 'Exception': str(e)})
    if ids:
        for current_id in ids:
            try:
                res += client.get_sensors(id=current_id)[1]
            except Exception as e:
                exceptions.append({'Query': f'id: {current_id}', 'Exception': str(e)})

    # Remove duplicates by taking entries with unique `id`:
    if res:
        res = list({v['id']: v for v in res}.values())

    endpoints = []
    command_results = []
    for sensor in res:
        is_isolated = _get_isolation_status_field(sensor['network_isolation_enabled'],
                                                  sensor['is_isolating'])
        endpoint = Common.Endpoint(
            id=sensor.get('id'),
            hostname=sensor.get('computer_name'),
            ip_address=_parse_field(sensor.get('network_adapters', ''), index_after_split=0, chars_to_remove='|'),
            mac_address=_parse_field(sensor.get('network_adapters', ''), index_after_split=1, chars_to_remove='|'),
            os_version=sensor.get('os_environment_display_string'),
            memory=sensor.get('physical_memory_size'),
            status='Online' if sensor.get('status') == 'Online' else 'Offline',
            is_isolated=is_isolated,
            vendor='Carbon Black Response')
        endpoints.append(endpoint)

        endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
        md = tableToMarkdown(f'{INTEGRATION_NAME} -  Endpoint: {sensor.get("id")}', endpoint_context)

        command_results.append(CommandResults(
            readable_output=md,
            raw_response=res,
            indicator=endpoint
        ))
    if exceptions:
        md = tableToMarkdown('The following queries resulted in an error: ', exceptions, headers=['Query', 'Exception'])
        command_results.append(CommandResults(readable_output=md))
    return command_results


def fetch_incidents(client: Client, max_results: int, last_run: dict, first_fetch_time: str, status: str = None,
                    feedname: str = None, query: str = ''):
    if (status or feedname) and query:
        raise Exception(f'{INTEGRATION_NAME} - Search is not permitted with both query and filter parameters.')

    max_results = arg_to_number(arg=max_results, arg_name='max_fetch', required=False) if max_results else 50

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = dateparser.parse(first_fetch_time)
    last_fetch = last_run.get('last_fetch', None)  # {last_fetch: timestamp}
    demisto.debug(f'{INTEGRATION_NAME} - last fetch: {last_fetch}')

    # Handle first fetch time
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = datetime.fromtimestamp(last_fetch)

    latest_created_time = last_fetch.timestamp()

    date_range = f'[{last_fetch.strftime("%Y-%m-%dT%H:%M:%S")} TO *]'

    incidents: list[dict[str, Any]] = []

    alerts = []
    time_sort = 'created_time'

    # multiple statuses are not supported by api. If multiple statuses provided, gets the incidents for each status.
    # Otherwise will run without status.
    query_params = {'created_time': date_range}
    if feedname:
        query_params['feedname'] = feedname

    if status:
        for current_status in argToList(status):
            demisto.debug(f'{INTEGRATION_NAME} - Fetching incident from Server with status: {current_status}')
            query_params['status'] = f'"{current_status}"'
            # we create a new query containing params since we do not allow both query and params.
            res = client.get_alerts(query=_create_query_string(query_params),
                                    limit=max_results, sort=time_sort)  # type: ignore[arg-type]
            alerts += res.get('results', [])
            demisto.debug(f'{INTEGRATION_NAME} - fetched {len(alerts)} so far.')
    else:
        query = _add_to_current_query(query, query_params)
        demisto.debug(f'{INTEGRATION_NAME} - Fetching incident from Server with status: {status}')
        res = client.get_alerts(query=query, limit=max_results, sort=time_sort)
        alerts += res.get('results', [])

    demisto.debug(f'{INTEGRATION_NAME} - Got total of {len(alerts)} alerts from CB server.')
    for alert in alerts:
        incident_created_time = dateparser.parse(alert.get('created_time'))
        assert incident_created_time is not None
        incident_created_time_ms = incident_created_time.timestamp()

        # to prevent duplicates, adding incidents with creation_time > last fetched incident
        if last_fetch and (incident_created_time_ms <= last_fetch.timestamp()):
            demisto.debug(f'{INTEGRATION_NAME} - alert {str(alert)} was created at {incident_created_time_ms}.'
                          f' Skipping.')
            continue

        alert_id = alert.get('unique_id', '')
        alert_name = alert.get('process_name', '')
        incident_name = f'{INTEGRATION_NAME}: {alert_id} {alert_name}'
        if not alert_id or not alert_name:
            demisto.debug(f'{INTEGRATION_NAME} - Alert details are missing. {str(alert)}')

        if ioc_attr := alert.get('ioc_attr'):
            try:
                alert['ioc_attr'] = json.loads(ioc_attr)
                highlights = alert['ioc_attr'].get('highlights', [])
                for i, attribute in enumerate(highlights):
                    highlights[i] = attribute.replace("PREPREPRE", "").replace("POSTPOSTPOST", "")
            except json.JSONDecodeError as e:
                demisto.debug(f"Failed to parse ioc_attr as JSON: {e}")

        incident = {
            'name': incident_name,
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(alert),
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time_ms > latest_created_time:
            latest_created_time = incident_created_time_ms

    demisto.debug(f'Fetched {len(alerts)} alerts. Saving {len(incidents)} as incidents.')
    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def test_module(client: Client, params: dict) -> str:
    try:
        client.get_processes(limit='5', allow_empty=True)
        if params['isFetch']:
            client.get_alerts(status=params.get('alert_status', None), feedname=params.get('alert_feed_name', None),
                              query=params.get('alert_query', None), allow_empty_params=False, limit='3')
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'UNAUTHORIZED' in str(e):
            raise Exception('Authorization Error: make sure API Key is correctly set')
        else:
            raise e


''' MAIN FUNCTION '''


def main() -> None:
    try:
        params = demisto.params()
        base_url = urljoin(params['url'], '/api')
        if not params.get('credentials') or not (api_token := params.get('credentials', {}).get('password')):
            raise DemistoException('Missing API Key. Fill in a valid key in the integration configuration.')
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        command = demisto.command()
        args = demisto.args() if demisto.args() else {}
        demisto.debug(f'Command being called is {command}')

        client = Client(
            base_url=base_url,
            use_ssl=verify_certificate,
            use_proxy=proxy,
            apitoken=api_token
        )
        commands: dict[str, Callable] = {'cb-edr-processes-search': processes_search_command,
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
                                         'cb-edr-watchlist-update-action': watchlist_update_action_command,
                                         'cb-edr-watchlist-delete': watchlist_delete_command,
                                         'cb-edr-sensors-list': sensors_list_command,
                                         'cb-edr-quarantine-device': quarantine_device_command,
                                         'cb-edr-unquarantine-device': unquarantine_device_command,
                                         'cb-edr-sensor-installer-download': sensor_installer_download_command,
                                         'endpoint': endpoint_command
                                         }

        if command == 'test-module':
            result = test_module(client, params)
            return_results(result)

        elif command == 'fetch-incidents':

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=params.get('max_fetch'),
                last_run=demisto.getLastRun(),
                first_fetch_time=params.get('first_fetch', '3 days'),
                status=params.get('alert_status', None),
                feedname=params.get('alert_feed_name', None),
                query=params.get('alert_query', None))
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](client, **args))
        else:
            raise NotImplementedError(f'command {command} was not implemented in this integration.')
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
