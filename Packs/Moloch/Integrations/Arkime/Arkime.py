# ----------------------------------------- Imports ---------------------------
import copy
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests.auth import HTTPDigestAuth

# ----------------------------------------- Constants ---------------------------
DEFAULT_COUNTS = '0'
DEFAULT_DATE = '1'
DEFAULT_INTERNAL_LIMIT = 50
DEFAULT_LIMIT = 100
MAX_FILES_LIST = 10000
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
DEFAULT_OFFSET = 0


# ----------------------------------------- Client ---------------------------
class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def connections_csv_request(self, srcField, dstField, date, expression, startTime, stopTime, view, order, fields,
                                bounding, strictly, length, start):
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
                               length=length,
                               start=start,
                               )
        headers = self._headers

        response = self._http_request('POST', 'api/connections/csv', params=params, headers=headers,
                                      resp_type='response')

        return response

    def get_connections_request(self, srcField, dstField, date, expression, startTime, stopTime, view, order, fields,
                                bounding, strictly, baselineDate, baselineVis, length, page_number, page_size):
        start = page_number * page_size
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
        response = self._http_request('POST', 'api/connections', params=params, headers=headers)

        return response

    def get_files_request(self, length, page_number, page_size):
        start = page_number * page_size
        params = assign_params(length=length, start=start)
        headers = self._headers

        response = self._http_request('GET', 'api/files', params=params, headers=headers)

        return response

    def sessions_query_request(self, date, expression, startTime, stopTime, view, order, fields, bounding,
                               strictly, length, page_number, page_size):
        start = page_number * page_size
        params = assign_params(date=date,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly,
                               length=length,
                               start=start,
                               )

        headers = self._headers

        response = self._http_request('POST', 'api/sessions', params=params, headers=headers)

        return response

    def sessions_csv_request(self, date, expression, startTime, stopTime, view, order, fields, bounding,
                             strictly, length, start):
        params = assign_params(date=date,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly,
                               length=length,
                               start=start,
                               )
        headers = self._headers

        response = self._http_request('POST', 'api/sessions/csv', params=params, headers=headers, resp_type='response')

        return response

    def sessions_pcap_request(self, ids, expression, startTime, stopTime):
        params = assign_params(ids=ids,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               )

        headers = self._headers

        response = self._http_request('GET', 'api/sessions/pcap', params=params, headers=headers, resp_type='response')

        return response

    def spi_graph_request(self, ids, date, expression, startTime, stopTime, view, fields, bounding, strictly):
        params = assign_params(ids=ids,
                               date=date,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               view=view,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly,
                               )
        headers = self._headers

        response = self._http_request('POST', 'api/spigraph', params=params, headers=headers)

        return response

    def spi_view_request(self, spi, date, expression, startTime, stopTime, view, fields, bounding, strictly):
        params = assign_params(spi=spi,
                               date=date,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               view=view,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly,
                               )
        headers = self._headers

        response = self._http_request('POST', 'api/spiview', params=params, headers=headers)

        return response

    def get_fields_request(self, array):
        params = assign_params(array=array)
        headers = self._headers

        response = self._http_request('GET', 'api/fields', params=params, headers=headers)

        return response

    def unique_field_request(self, counts, exp, date, expression, startTime, stopTime, view, order, fields, bounding,
                             strictly):
        params = assign_params(counts=counts,
                               exp=exp,
                               date=date,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly)
        headers = self._headers

        response = self._http_request('POST', 'api/unique', params=params, headers=headers, resp_type='response')

        return response

    def unique_field_multi_request(self, counts, exp, field, date, expression, startTime, stopTime, view, order, fields,
                                   bounding, strictly):
        params = assign_params(counts=counts,
                               exp=exp,
                               filed=field,
                               date=date,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly)
        headers = self._headers

        response = self._http_request('POST', 'api/multiunique', params=params, headers=headers, resp_type='response')

        return response

    def add_session_tags_request(self, tags, ids, segments, date, expression, startTime, stopTime, view,
                                 order, fields, bounding, strictly):
        params = assign_params(tags=tags,
                               ids=ids,
                               segments=segments,
                               date=date,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly)
        headers = self._headers

        response = self._http_request('POST', 'api/sessions/addtags', params=params, headers=headers)

        return response

    def remove_session_tags_request(self, tags, ids, segments, date, expression, startTime, stopTime, view,
                                    order, fields, bounding, strictly):
        params = assign_params(tags=tags,
                               ids=ids,
                               segments=segments,
                               date=date,
                               expression=expression,
                               startTime=startTime,
                               stopTime=stopTime,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly)
        headers = self._headers

        response = self._http_request('POST', 'api/sessions/removetags', params=params, headers=headers)

        return response


# ----------------------------------------- Helper functions ---------------------------

def header_transform_1(header):
    mapping = {'id': 'Source IP',
               'cnt': 'Count',
               'sessions': 'Sessions',
               'node': 'Node',
               'name': 'Name',
               'num': 'Number',
               'first': 'First',
               'filesize': 'File Size',
               'packetsSize': 'Packet Size',
               'friendlyName': 'Friendly Name',
               'type': 'Type',
               'group': 'Group',
               'help': 'Help',
               'dbField': 'DB Field',
               }

    if header in mapping:
        return mapping[header]
    return header


def header_transform_2(header):
    mapping = {'id': 'ID',
               'ipProtocol': 'IP Protocol',
               'source.ip': 'Source IP',
               'source.port': 'Source Port',
               'destination.ip': 'Destination IP',
               'destination.port': 'Destination Port',
               'node': 'Node',
               'firstPacket': 'First Packet',
               'lastPacket': 'Last Packet',
               'success': 'Success',
               'text': 'Text',
               }
    if header in mapping:
        return mapping[header]
    return header


def arrange_output_for_pcap_file_list_command(response: Dict) -> List:
    """
    This function converting data.first to timestamp for human-readable.
    """
    output_for_hr = []
    for record in response.get('data'):
        temp_record = copy.deepcopy(record)
        temp_record['first'] = epochToTimestamp(temp_record['first'])
        output_for_hr.append(temp_record)
    return output_for_hr


def arrange_output_for_session_list_command(response: Dict) -> List:
    headers = ['id', 'ipProtocol', 'source.ip', 'source.port', 'destination.ip', 'destination.port', 'node']

    output_for_hr = []

    for record in response.get('data'):
        # temp_record = copy.deepcopy(record)
        temp_record = {'firstPacket': epochToTimestamp(record['firstPacket']),
                       'lastPacket': epochToTimestamp(record['lastPacket'])}
        for header in headers:
            if '.' in header:
                keys = header.split('.')
                temp_record[header] = record.get(keys[0]).get(keys[1])
            else:
                temp_record[header] = record.get(header)
        output_for_hr.append(temp_record)
    return output_for_hr


def page_size_validness(page_size: int) -> int:
    if page_size < MIN_PAGE_SIZE:
        return MIN_PAGE_SIZE
    elif page_size > MAX_PAGE_SIZE:
        return MAX_PAGE_SIZE
    return page_size


def remove_all_keys_endswith_histo(response: Dict) -> Dict:
    for key, value in response.copy().items():
        if key.endswith('Histo'):
            del response[key]
        elif isinstance(response[key], dict):
            response[key] = remove_all_keys_endswith_histo(response[key])
        elif isinstance(response[key], List):
            response[key] = [remove_all_keys_endswith_histo(response[key][0])]

    return response


def parse_unique_field_response(text: str) -> List:
    text = text.split('\n')
    unique_field_list_for_hr = []
    for line in text:
        line = line.split(',')
        temp_dic = {'Field': line[0]}
        if len(line) > 1:
            temp_dic['Count'] = line[1]
        unique_field_list_for_hr.append(temp_dic)
    return unique_field_list_for_hr


def unique_field_helper(response, start, limit) -> CommandResults:
    headers = ['Field', 'Count']
    unique_field_list = parse_unique_field_response(response.text)
    unique_field_list = unique_field_list[start: start + limit]
    command_results = CommandResults(
        outputs_prefix='Arkime.UniqueField',
        outputs=unique_field_list,
        raw_response=unique_field_list,
        readable_output=tableToMarkdown('Unique Field Results:',
                                        unique_field_list,
                                        headers=headers,
                                        )
    )

    return command_results


# ----------------------------------------- Command functions ---------------------------

def connection_csv_get_command(client: Client, args: Dict[str, Any]) -> Dict:
    """
    Gets a list of nodes and links in csv format and returns them to the client.
    """
    srcField = args.get('source_field')
    dstField = args.get('destination_field')
    date = arg_to_number(args.get('date'))
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    order = args.get('order')
    fields = args.get('fields')
    bounding = args.get('bounding')
    strictly = args.get('strictly')
    length = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    start = arg_to_number(args.get('offset', DEFAULT_OFFSET))

    response = client.connections_csv_request(srcField=srcField,
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
                                              length=length,
                                              start=start,
                                              )

    return fileResult(filename='connections_list.csv', data=response.content, file_type=EntryType.ENTRY_INFO_FILE)


def connection_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets a list of nodes and links and returns them to the client.
    """
    srcField = args.get('source_field')
    dstField = args.get('destination_field')
    date = arg_to_number(args.get('date'))
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
    length = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    page_number = arg_to_number(args.get('page_number', DEFAULT_OFFSET))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    page_size = page_size_validness(page_size)

    response = client.get_connections_request(srcField=srcField,
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
                                              page_number=page_number,
                                              page_size=page_size,
                                              )

    headers = ['id', 'cnt', 'sessions', 'node']
    command_results = CommandResults(
        outputs_prefix='Arkime.Connection',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Connection Results:',
                                        response.get('nodes'),
                                        headerTransform=header_transform_1,
                                        headers=headers,
                                        )
    )

    return command_results


def pcap_file_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets a list of PCAP files that Arkime knows about.
    """
    length = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    length = length if length <= MAX_FILES_LIST else MAX_FILES_LIST

    page_number = arg_to_number(args.get('page_number', DEFAULT_OFFSET))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    page_size = page_size_validness(page_size)

    response = client.get_files_request(length=length,
                                        page_number=page_number,
                                        page_size=page_size,
                                        )
    output_for_hr = arrange_output_for_pcap_file_list_command(response)
    headers = ['node', 'name', 'num', 'first', 'filesize', 'packetsSize']

    command_results = CommandResults(
        outputs_prefix='Arkime.PcapFile',
        outputs_key_field='name',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Files List Result:',
                                        output_for_hr,
                                        headerTransform=header_transform_1,
                                        headers=headers,
                                        )
    )

    return command_results


def session_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    date = arg_to_number(args.get('date'))
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    order = args.get('order')
    fields = args.get('fields')
    bounding = args.get('bounding')
    strictly = args.get('strictly')
    length = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    page_number = arg_to_number(args.get('page_number', DEFAULT_OFFSET))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    page_size = page_size_validness(page_size)

    response = client.sessions_query_request(date=date,
                                             expression=expression,
                                             startTime=startTime,
                                             stopTime=stopTime,
                                             view=view,
                                             order=order,
                                             fields=fields,
                                             bounding=bounding,
                                             strictly=strictly,
                                             length=length,
                                             page_number=page_number,
                                             page_size=page_size,
                                             )
    output_for_hr = arrange_output_for_session_list_command(response)
    headers = ['id', 'ipProtocol', 'firstPacket', 'lastPacket', 'source.ip', 'source.port', 'destination.ip',
               'destination.port', 'node']

    command_results = CommandResults(
        outputs_prefix='Arkime.Session',
        outputs_key_field='',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Session List Result:',
                                        output_for_hr,
                                        headerTransform=header_transform_2,
                                        headers=headers,
                                        )
    )

    return command_results


def sessions_csv_get_command(client: Client, args: Dict[str, Any]) -> Dict:
    date = arg_to_number(args.get('date'))
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    order = args.get('order')
    fields = args.get('fields')
    bounding = args.get('bounding')
    strictly = args.get('strictly')
    length = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    start = arg_to_number(args.get('offset', DEFAULT_OFFSET))

    response = client.sessions_csv_request(date=date,
                                           expression=expression,
                                           startTime=startTime,
                                           stopTime=stopTime,
                                           view=view,
                                           order=order,
                                           fields=fields,
                                           bounding=bounding,
                                           strictly=strictly,
                                           length=length,
                                           start=start,
                                           )

    return fileResult(filename='sessions_list.csv', data=response.content, file_type=EntryType.ENTRY_INFO_FILE)


def sessions_pcap_get_command(client: Client, args: Dict[str, Any]) -> Dict:
    ids = args.get('ids')
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')

    response = client.sessions_pcap_request(ids=ids,
                                            expression=expression,
                                            startTime=startTime,
                                            stopTime=stopTime,
                                            )

    return fileResult(filename='raw_session_data.pcap', data=response.content, file_type=EntryType.ENTRY_INFO_FILE)


def spigraph_get_command(client: Client, args: Dict[str, Any]) -> dict:
    ids = args.get('field')
    date = arg_to_number(args.get('date'))
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    fields = args.get('fields')
    bounding = args.get('bounding')
    strictly = args.get('strictly')

    response = client.spi_graph_request(ids=ids,
                                        date=date,
                                        expression=expression,
                                        startTime=startTime,
                                        stopTime=stopTime,
                                        view=view,
                                        fields=fields,
                                        bounding=bounding,
                                        strictly=strictly,
                                        )
    # filter response - omit all keys in json end with Histo
    response = remove_all_keys_endswith_histo(response)

    return fileResult(filename='spi_graph.json', data=str(response), file_type=EntryType.ENTRY_INFO_FILE)


def spiview_get_command(client: Client, args: Dict[str, Any]) -> dict:
    spi = argToList(args.get('spi'))
    date = arg_to_number(args.get('date', 1))
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    fields = args.get('fields')
    bounding = args.get('bounding', 'last')
    strictly = args.get('strictly', False)

    response = client.spi_view_request(spi=spi,
                                       date=date,
                                       expression=expression,
                                       startTime=startTime,
                                       stopTime=stopTime,
                                       view=view,
                                       fields=fields,
                                       bounding=bounding,
                                       strictly=strictly,
                                       )
    return fileResult(filename='spi_view.json', data=str(response), file_type=EntryType.ENTRY_INFO_FILE)


def fields_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    array = args.get('array_response', False)
    limit = arg_to_number(args.get('limit', DEFAULT_INTERNAL_LIMIT))
    page_number = arg_to_number(args.get('page_number', DEFAULT_OFFSET))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    page_size = page_size_validness(page_size)

    response = client.get_fields_request(array)
    start = page_size * page_number
    response = response[start:start + limit]

    headers = ['friendlyName', 'type', 'group', 'help', 'dbField']
    command_results = CommandResults(
        outputs_prefix='Arkime.Fields',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Fields Results:',
                                        response,
                                        headerTransform=header_transform_1,
                                        headers=headers,
                                        )
    )

    return command_results


def unique_field_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    counts = arg_to_number(args.get('counts', DEFAULT_COUNTS))
    exp = args.get('expression_field_names')
    date = arg_to_number(args.get('date', DEFAULT_DATE))
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    order = args.get('order')
    fields = args.get('fields')
    bounding = args.get('bounding', 'last')
    strictly = args.get('strictly', False)
    limit = arg_to_number(args.get('limit', DEFAULT_INTERNAL_LIMIT))
    page_number = arg_to_number(args.get('page_number', DEFAULT_OFFSET))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    page_size = page_size_validness(page_size)
    start = page_number * page_size

    response = client.unique_field_request(counts=counts,
                                           exp=exp,
                                           date=date,
                                           expression=expression,
                                           startTime=startTime,
                                           stopTime=stopTime,
                                           view=view,
                                           order=order,
                                           fields=fields,
                                           bounding=bounding,
                                           strictly=strictly,
                                           )

    return unique_field_helper(response, start, limit)


def multi_unique_field_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    counts = arg_to_number(args.get('counts', DEFAULT_COUNTS))
    exp = args.get('expression_field_names')
    field = args.get('database_field')
    date = arg_to_number(args.get('date', DEFAULT_DATE))
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    order = args.get('order')
    fields = args.get('fields')
    bounding = args.get('bounding', 'last')
    strictly = args.get('strictly', False)
    limit = arg_to_number(args.get('limit', DEFAULT_INTERNAL_LIMIT))
    page_number = arg_to_number(args.get('page_number', DEFAULT_OFFSET))
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    page_size = page_size_validness(page_size)
    start = page_number * page_size

    response = client.unique_field_multi_request(counts=counts,
                                                 exp=exp,
                                                 field=field,
                                                 date=date,
                                                 expression=expression,
                                                 startTime=startTime,
                                                 stopTime=stopTime,
                                                 view=view,
                                                 order=order,
                                                 fields=fields,
                                                 bounding=bounding,
                                                 strictly=strictly,
                                                 )

    return unique_field_helper(response, start, limit)


def session_tag_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    tags = args.get('tags')
    ids = args.get('session_ids')
    segments = args.get('segments', 'no')
    date = arg_to_number(args.get('date', DEFAULT_DATE))
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    order = args.get('order')
    fields = args.get('fields')
    bounding = args.get('bounding', 'last')
    strictly = args.get('strictly', False)

    response = client.add_session_tags_request(tags=tags,
                                               ids=ids,
                                               segments=segments,
                                               date=date,
                                               expression=expression,
                                               startTime=startTime,
                                               stopTime=stopTime,
                                               view=view,
                                               order=order,
                                               fields=fields,
                                               bounding=bounding,
                                               strictly=strictly,
                                               )
    headers = ['success', 'text']
    command_results = CommandResults(
        outputs_prefix='Arkime.Tag',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Session Tag Results:',
                                        response,
                                        headers=headers,
                                        headerTransform=header_transform_2
                                        )
    )

    return command_results


def session_tag_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    tags = args.get('tags')
    ids = args.get('session_ids')
    segments = args.get('segments', 'no')
    date = arg_to_number(args.get('date', DEFAULT_DATE))
    expression = args.get('expression')
    startTime = args.get('start_time')
    stopTime = args.get('stop_time')
    view = args.get('view')
    order = args.get('order')
    fields = args.get('fields')
    bounding = args.get('bounding', 'last')
    strictly = args.get('strictly', False)

    response = client.remove_session_tags_request(tags=tags,
                                                  ids=ids,
                                                  segments=segments,
                                                  date=date,
                                                  expression=expression,
                                                  startTime=startTime,
                                                  stopTime=stopTime,
                                                  view=view,
                                                  order=order,
                                                  fields=fields,
                                                  bounding=bounding,
                                                  strictly=strictly,
                                                  )
    headers = ['success', 'text']
    command_results = CommandResults(
        outputs_prefix='Arkime.Tag',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Session Tag Results:',
                                        response,
                                        headers=headers,
                                        headerTransform=header_transform_2
                                        )
    )

    return command_results


# ----------------------------------------- from generation ---------------------------

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
            'arkime-connection-csv-get': connection_csv_get_command,
            'arkime-connection-list': connection_list_command,
            'arkime-pcap-file-list': pcap_file_list_command,
            'arkime-session-list': session_list_command,
            'arkime-session-csv-get': sessions_csv_get_command,
            'arkime-session-pcap-get': sessions_pcap_get_command,
            'arkime-spigraph-get': spigraph_get_command,
            'arkime-spiview-get': spiview_get_command,
            'arkime-field-list': fields_list_command,
            'arkime-unique-field-list': unique_field_list_command,
            'arkime-multi-unique-field-list': multi_unique_field_list_command,
            'arkime-session-tag-add': session_tag_add_command,
            'arkime-session-tag-remove': session_tag_remove_command,
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
