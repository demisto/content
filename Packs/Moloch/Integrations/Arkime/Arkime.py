import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests.auth import HTTPDigestAuth


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def get_connections_request(self, srcField, dstField, date, expression, startTime, stopTime, view, order, fields,
                                bounding, strictly, baselineDate, baselineVis, length, start):
        params = assign_params(srcField=srcField,
                               dstField=dstField,
                               date=date,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly,
                               baselineDate=baselineDate,
                               baselineVis=baselineVis,
                               length=length,
                               start=start,
                               )

        headers = self._headers
        # params['username'] = self._headers.get('username')
        # params['password'] = self._headers.get('password')
        # params['UseAuthDigest'] = 'true'
        response = self._http_request('POST', 'api/connections', params=params, headers=headers)

        return response

    def connections_csv_request(self, srcfield, dstfield, starttime, stoptime):
        params = assign_params(srcField=srcfield, dstField=dstfield, startTime=starttime, stopTime=stoptime)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'api/connections/csv', params=params, headers=headers)

        return response

    def get_raw_session_request(self):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request(
            'GET', 'api/session/localhost/3@220417-Yg7OpiE4Pi1PFaRqu8lztuA6/pcap', headers=headers)

        return response

    def sessions_pcap_request(self, ids, starttime, segments, stoptime):
        params = assign_params(ids=ids, startTime=starttime, segments=segments, stopTime=stoptime)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', 'api/sessions/pcap', params=params, headers=headers)

        return response

    def sessions_csv_request(self, stoptime, starttime):
        params = assign_params(stopTime=stoptime, startTime=starttime)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'api/sessions/csv', params=params, headers=headers)

        return response

    def sessions_query_request(self, stoptime, starttime, date):
        params = assign_params(stopTime=stoptime, startTime=starttime, date=date)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'api/sessions', params=params, headers=headers)

        return response

    def unique_field_request(self, counts, exp, date, expression, start, length, stoptime, starttime, view, order,
                             bounding, fields, strictly):
        params = assign_params(counts=counts, exp=exp, date=date, expression=expression, start=start, length=length,
                               stopTime=stoptime, startTime=starttime, view=view, order=order, bounding=bounding,
                               fields=fields, strictly=strictly)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', 'api/unique', params=params, headers=headers)

        return response

    def unique_field_multi_request(self, counts, exp, field, date, expression, start, length, stoptime, starttime, view,
                                   order, bounding, fields, strictly):
        params = assign_params(counts=counts, exp=exp, field=field, date=date, expression=expression, start=start,
                               length=length,
                               stopTime=stoptime, startTime=starttime, view=view, order=order, bounding=bounding,
                               fields=fields, strictly=strictly)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'api/multiunique', params=params, headers=headers)

        return response

    def get_fields_request(self, array):
        params = assign_params(array=array)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', 'api/fields', params=params, headers=headers)

        return response

    def spi_data_request(self, nodename, filenum, date, expression, start, length, stoptime, starttime, view, order,
                         bounding, fields, strictly):
        params = assign_params(date=date, expression=expression, start=start, length=length, stopTime=stoptime,
                               startTime=starttime, view=view, order=order, bounding=bounding, fields=fields,
                               strictly=strictly)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', f'api/{nodename}/{filenum}/filesize', params=params, headers=headers)

        return response

    def spi_graph_request(self, field, starttime, stoptime):
        params = assign_params(field=field, startTime=starttime, stopTime=stoptime)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'api/spigraph', params=params, headers=headers)

        return response

    def spi_view_request(self, spi, date, expression, start, length, stoptime, starttime, view, order, bounding, fields,
                         strictly):
        params = assign_params(spi=spi, date=date, expression=expression, start=start, length=length, stopTime=stoptime,
                               startTime=starttime, view=view, order=order, bounding=bounding, fields=fields,
                               strictly=strictly)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'api/spiview', params=params, headers=headers)

        return response

    def new_request_request(self):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', '_cat/health', headers=headers)

        return response

    def get_file_size_request(self, nodename, filenum):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', f'api/{nodename}/{filenum}/filesize', headers=headers)

        return response

    def default_command_request(self, nodename, filenum, date, expression, start, length, stoptime, starttime, view,
                                order, bounding, fields, strictly):
        params = assign_params(date=date, expression=expression, start=start, length=length, stopTime=stoptime,
                               startTime=starttime, view=view, order=order, bounding=bounding, fields=fields,
                               strictly=strictly)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', f'api/{nodename}/{filenum}/filesize', params=params, headers=headers)

        return response

    def reverse_dns_request(self, ip):
        params = assign_params(ip=ip)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', 'api/reversedns', params=params, headers=headers)

        return response

    def add_session_tags_request(self, tags, ids, segments, date, expression, start, length, stoptime, starttime, view,
                                 order, bounding, fields, strictly):
        params = assign_params(tags=tags, ids=ids, segments=segments, date=date, expression=expression, start=start,
                               length=length,
                               stopTime=stoptime, startTime=starttime, view=view, order=order, bounding=bounding,
                               fields=fields, strictly=strictly)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'api/sessions/addtags', params=params, headers=headers)

        return response

    def get_files_request(self, length, start):
        params = assign_params(length=length, start=start)
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', 'api/files', params=params, headers=headers)

        return response

    def histories_get_request(self):
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('GET', 'api/histories', headers=headers)

        return response


def connection_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    srcField = args.get('source_field')
    dstField = args.get('destination_field')
    date = args.get('date')
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    order = args.get('order')
    fields = args.get('fields')
    bounding = args.get('bounding')
    strictly = args.get('strictly')
    baselineDate = args.get('baseline_date')
    baselineVis = args.get('baseline_view')
    length = args.get('limit')
    start = args.get('offset')

    response = client.get_connections_request(srcField,
                                              dstField,
                                              date,
                                              expression,
                                              startTime,
                                              stopTime,
                                              view,
                                              order,
                                              fields,
                                              bounding,
                                              strictly,
                                              baselineDate,
                                              baselineVis,
                                              length,
                                              start,
                                              )
    headers = ['Source IP', 'count', 'Sessions', 'Node']
    readable_response = []
    for record in response.get('nodes'):
        readable_response.append({'Source IP': record.get('id'),
                                  'count': record.get('cnt'),
                                  'Sessions': record.get('sessions'),
                                  'Node': [node for node in record.get('node')]
                                  })
    command_results = CommandResults(
        outputs_prefix='Arkime.Connection',
        outputs_key_field='',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Connection Results:',
                                        readable_response,
                                        removeNull=True,
                                        headers=headers,
                                        )
    )

    return command_results


def connections_csv_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    srcField = args.get('source_field')
    dstField = args.get('destination_field')
    date = args.get('date')
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    order = args.get('order')

    fields = args.get('fields')
    bounding = args.get('bounding')
    strictly = args.get('strictly')
    length = args.get('limit')
    order = args.get('order')

    response = client.connections_csv_request(srcfield, dstfield, starttime, stoptime)
    command_results = CommandResults(
        outputs_prefix='Arkime.ConnectionsCsv',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_raw_session_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.get_raw_session_request()
    command_results = CommandResults(
        outputs_prefix='Arkime.GetRawSession',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def sessions_pcap_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ids = args.get('ids')
    starttime = args.get('starttime')
    segments = args.get('segments')
    stoptime = args.get('stoptime')

    response = client.sessions_pcap_request(ids, starttime, segments, stoptime)
    command_results = CommandResults(
        outputs_prefix='Arkime.SessionsPcap',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def sessions_csv_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    stoptime = args.get('stoptime')
    starttime = args.get('starttime')

    response = client.sessions_csv_request(stoptime, starttime)
    command_results = CommandResults(
        outputs_prefix='Arkime.SessionsCsv',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def sessions_query_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    stoptime = args.get('stoptime')
    starttime = args.get('starttime')
    date = args.get('date')

    response = client.sessions_query_request(stoptime, starttime, date)
    command_results = CommandResults(
        outputs_prefix='Arkime.SessionsQuery',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def unique_field_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    counts = args.get('counts')
    exp = args.get('exp')
    date = args.get('date')
    expression = args.get('expression')
    start = args.get('start')
    length = args.get('length')
    stoptime = args.get('stoptime')
    starttime = args.get('starttime')
    view = args.get('view')
    order = args.get('order')
    bounding = args.get('bounding')
    fields = args.get('fields')
    strictly = args.get('strictly')

    response = client.unique_field_request(counts, exp, date, expression, start,
                                           length, stoptime, starttime, view, order, bounding, fields, strictly)
    command_results = CommandResults(
        outputs_prefix='Arkime.UniqueField',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def unique_field_multi_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    counts = args.get('counts')
    exp = args.get('exp')
    field = args.get('field')
    date = args.get('date')
    expression = args.get('expression')
    start = args.get('start')
    length = args.get('length')
    stoptime = args.get('stoptime')
    starttime = args.get('starttime')
    view = args.get('view')
    order = args.get('order')
    bounding = args.get('bounding')
    fields = args.get('fields')
    strictly = args.get('strictly')

    response = client.unique_field_multi_request(
        counts, exp, field, date, expression, start, length, stoptime, starttime, view, order, bounding, fields,
        strictly)
    command_results = CommandResults(
        outputs_prefix='Arkime.UniqueFieldMulti',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_fields_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    array = args.get('array')

    response = client.get_fields_request(array)
    command_results = CommandResults(
        outputs_prefix='Arkime.GetFields',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def spi_data_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    nodename = args.get('nodename')
    filenum = args.get('filenum')
    date = args.get('date')
    expression = args.get('expression')
    start = args.get('start')
    length = args.get('length')
    stoptime = args.get('stoptime')
    starttime = args.get('starttime')
    view = args.get('view')
    order = args.get('order')
    bounding = args.get('bounding')
    fields = args.get('fields')
    strictly = args.get('strictly')

    response = client.spi_data_request(nodename, filenum, date, expression, start,
                                       length, stoptime, starttime, view, order, bounding, fields, strictly)
    command_results = CommandResults(
        outputs_prefix='Arkime.SpiData',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def spi_graph_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    field = args.get('field')
    starttime = args.get('starttime')
    stoptime = args.get('stoptime')

    response = client.spi_graph_request(field, starttime, stoptime)
    command_results = CommandResults(
        outputs_prefix='Arkime.SpiGraph',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def spi_view_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    spi = args.get('spi')
    date = args.get('date')
    expression = args.get('expression')
    start = args.get('start')
    length = args.get('length')
    stoptime = args.get('stoptime')
    starttime = args.get('starttime')
    view = args.get('view')
    order = args.get('order')
    bounding = args.get('bounding')
    fields = args.get('fields')
    strictly = args.get('strictly')

    response = client.spi_view_request(spi, date, expression, start, length, stoptime,
                                       starttime, view, order, bounding, fields, strictly)
    command_results = CommandResults(
        outputs_prefix='Arkime.SpiView',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def new_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.new_request_request()
    command_results = CommandResults(
        outputs_prefix='Arkime.NewRequest',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_file_size_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    nodename = args.get('nodename')
    filenum = args.get('filenum')

    response = client.get_file_size_request(nodename, filenum)
    command_results = CommandResults(
        outputs_prefix='Arkime.GetFileSize',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def default_command_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    nodename = args.get('nodename')
    filenum = args.get('filenum')
    date = args.get('date')
    expression = args.get('expression')
    start = args.get('start')
    length = args.get('length')
    stoptime = args.get('stoptime')
    starttime = args.get('starttime')
    view = args.get('view')
    order = args.get('order')
    bounding = args.get('bounding')
    fields = args.get('fields')
    strictly = args.get('strictly')

    response = client.default_command_request(
        nodename, filenum, date, expression, start, length, stoptime, starttime, view, order, bounding, fields,
        strictly)
    command_results = CommandResults(
        outputs_prefix='Arkime.DefaultCommand',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def reverse_dns_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ip = args.get('ip')

    response = client.reverse_dns_request(ip)
    command_results = CommandResults(
        outputs_prefix='Arkime.ReverseDns',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_session_tags_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    tags = args.get('tags')
    ids = args.get('ids')
    segments = args.get('segments')
    date = args.get('date')
    expression = args.get('expression')
    start = args.get('start')
    length = args.get('length')
    stoptime = args.get('stoptime')
    starttime = args.get('starttime')
    view = args.get('view')
    order = args.get('order')
    bounding = args.get('bounding')
    fields = args.get('fields')
    strictly = args.get('strictly')

    response = client.add_session_tags_request(
        tags, ids, segments, date, expression, start, length, stoptime, starttime, view, order, bounding, fields,
        strictly)
    command_results = CommandResults(
        outputs_prefix='Arkime.AddSessionTags',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_files_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    length = args.get('length')
    start = args.get('start')

    response = client.get_files_request(length, start)
    command_results = CommandResults(
        outputs_prefix='Arkime.GetFiles',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def histories_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    response = client.histories_get_request()
    command_results = CommandResults(
        outputs_prefix='Arkime.HistoriesGet',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    try:
        if connection_list_command(client=client, args={}):
            return_results('ok')
    except Exception as e:
        return_results(e)


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    auth = HTTPDigestAuth(params.get('credentials').get('identifier'), params.get('credentials').get('password'))
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {'Content-Type': 'application/json'}

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=auth)

        commands = {
            'arkime-connection-list': connection_list_command,
            'arkime-connection-csv-get': connections_csv_get_command,
            'arkime-get-raw-session': get_raw_session_command,
            'arkime-sessions-pcap': sessions_pcap_command,
            'arkime-sessions-csv': sessions_csv_command,
            'arkime-sessions-query': sessions_query_command,
            'arkime-unique-field': unique_field_command,
            'arkime-unique-field-multi': unique_field_multi_command,
            'arkime-get-fields': get_fields_command,
            'arkime-spi-data': spi_data_command,
            'arkime-spi-graph': spi_graph_command,
            'arkime-spi-view': spi_view_command,
            'arkime-new-request': new_request_command,
            'arkime-get-file-size': get_file_size_command,
            'arkime-default-command': default_command_command,
            'arkime-reverse-dns': reverse_dns_command,
            'arkime-add-session-tags': add_session_tags_command,
            'arkime-get-files': get_files_command,
            'arkime-histories-get': histories_get_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
