# ----------------------------------------- Imports ---------------------------
import copy
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests.auth import HTTPDigestAuth

# ----------------------------------------- Constants ---------------------------
DEFAULT_SEGMENTS = 'no'
DEFAULT_BOUNDING = 'last'
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

    def connections_csv_request(self, source_field, destination_field, date, expression, start_time, stop_time, view,
                                order, fields,
                                bounding, strictly, length, start):
        params = assign_params(srcField=source_field,
                               dstField=destination_field,
                               date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
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

    def get_connections_request(self, source_field, destination_field, date, expression, start_time, stop_time, view,
                                order, fields, bounding, strictly, baseline_date, baseline_view, length, page_number,
                                page_size):
        start = page_number * page_size

        params = assign_params(srcField=source_field,
                               dstField=destination_field,
                               date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly,
                               baselineDate=baseline_date,
                               baselineVis=baseline_view,
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

    def sessions_query_request(self, date, expression, start_time, stop_time, view, order, fields, bounding,
                               strictly, length, page_number, page_size):
        start = page_number * page_size

        params = assign_params(date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
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

    def sessions_csv_request(self, date, expression, start_time, stop_time, view, order, fields, bounding,
                             strictly, length, start):
        params = assign_params(date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
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

    def sessions_pcap_request(self, ids, expression, start_time, stop_time):
        params = assign_params(ids=ids,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
                               )

        headers = self._headers

        response = self._http_request('GET', 'api/sessions/pcap', params=params, headers=headers, resp_type='response')

        return response

    def spi_graph_request(self, ids, date, expression, start_time, stop_time, view, fields, bounding, strictly):
        params = assign_params(ids=ids,
                               date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
                               view=view,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly,
                               )

        headers = self._headers

        response = self._http_request('POST', 'api/spigraph', params=params, headers=headers)

        return response

    def spi_view_request(self, spi, date, expression, start_time, stop_time, view, fields, bounding, strictly):
        params = assign_params(spi=spi,
                               date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
                               view=view,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly,
                               )
        headers = self._headers

        response = self._http_request('POST', 'api/spiview', params=params, headers=headers)

        return response

    def get_fields_request(self, array_response):
        params = assign_params(array=array_response)

        headers = self._headers

        response = self._http_request('GET', 'api/fields', params=params, headers=headers)

        return response

    def unique_field_request(self, counts, expression_field_names, date, expression, start_time, stop_time, view, order,
                             fields, bounding, strictly):
        params = assign_params(counts=counts,
                               exp=expression_field_names,
                               date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly)

        headers = self._headers

        response = self._http_request('POST', 'api/unique', params=params, headers=headers, resp_type='response')

        return response

    def unique_field_multi_request(self, counts, expression_field_names, database_field, date, expression, start_time,
                                   stop_time,
                                   view, order, fields, bounding, strictly):
        params = assign_params(counts=counts,
                               exp=expression_field_names,
                               filed=database_field,
                               date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly)

        headers = self._headers

        response = self._http_request('POST', 'api/multiunique', params=params, headers=headers, resp_type='response')

        return response

    def add_session_tags_request(self, tags, ids, segments, date, expression, start_time, stop_time, view,
                                 order, fields, bounding, strictly):
        params = assign_params(tags=tags,
                               ids=ids,
                               segments=segments,
                               date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly)

        headers = self._headers

        response = self._http_request('POST', 'api/sessions/addtags', json_data=params, headers=headers)

        return response

    def remove_session_tags_request(self, tags, ids, segments, date, expression, start_time, stop_time, view, order,
                                    fields, bounding, strictly):
        params = assign_params(tags=tags,
                               ids=ids,
                               segments=segments,
                               date=date,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
                               view=view,
                               order=order,
                               fields=fields,
                               bounding=bounding,
                               strictly=strictly)

        headers = self._headers

        response = self._http_request('POST', 'api/sessions/removetags', headers=headers, json_data=params)

        return response


# ----------------------------------------- Helper functions ---------------------------

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

def connection_csv_get_command(client: Client,
                               source_field=None,
                               destination_field=None,
                               date=DEFAULT_DATE,
                               expression=None,
                               start_time=None,
                               stop_time=None,
                               view=None,
                               order=None,
                               fields=None,
                               bounding=None,
                               strictly=None,
                               limit=DEFAULT_LIMIT,
                               offset=DEFAULT_OFFSET) -> Dict:
    """
    Gets a list of nodes and links in csv format and returns them to the client.
    """
    date = arg_to_number(date)
    length = arg_to_number(limit)
    start = arg_to_number(offset)

    response = client.connections_csv_request(source_field=source_field,
                                              destination_field=destination_field,
                                              date=date,
                                              expression=expression,
                                              start_time=start_time,
                                              stop_time=stop_time,
                                              view=view,
                                              order=order,
                                              fields=fields,
                                              bounding=bounding,
                                              strictly=strictly,
                                              length=length,
                                              start=start,
                                              )

    return fileResult(filename='connections_list.csv', data=response.content, file_type=EntryType.ENTRY_INFO_FILE)


def connection_list_command(client: Client,
                            source_field=None,
                            destination_field=None,
                            date=DEFAULT_DATE,
                            expression=None,
                            start_time=None,
                            stop_time=None,
                            view=None,
                            order=None,
                            fields=None,
                            bounding=None,
                            strictly=None,
                            baseline_date=None,
                            baseline_view=None,
                            limit=DEFAULT_LIMIT,
                            page_number=DEFAULT_OFFSET,
                            page_size=DEFAULT_PAGE_SIZE) -> CommandResults:
    """
    Gets a list of nodes and links and returns them to the client.
    """
    date = arg_to_number(date)
    length = arg_to_number(limit)
    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)
    page_size = page_size_validness(page_size)

    response = client.get_connections_request(source_field=source_field,
                                              destination_field=destination_field,
                                              date=date,
                                              expression=expression,
                                              start_time=start_time,
                                              stop_time=stop_time,
                                              view=view,
                                              order=order,
                                              fields=fields,
                                              bounding=bounding,
                                              strictly=strictly,
                                              baseline_date=baseline_date,
                                              baseline_view=baseline_view,
                                              length=length,
                                              page_number=page_number,
                                              page_size=page_size,
                                              )

    headers = ['id', 'cnt', 'sessions', 'node']
    mapping = {'id': 'Source IP',
               'cnt': 'Count',
               'sessions': 'Sessions',
               'node': 'Node'}
    command_results = CommandResults(
        outputs_prefix='Arkime.Connection',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Connection Results:',
                                        response.get('nodes'),
                                        headerTransform=lambda header: mapping.get(header, header),
                                        headers=headers,
                                        )
    )

    return command_results


def pcap_file_list_command(client: Client,
                           limit=DEFAULT_LIMIT,
                           page_number=DEFAULT_OFFSET,
                           page_size=DEFAULT_PAGE_SIZE) -> CommandResults:
    """
    Gets a list of PCAP files that Arkime knows about.
    """
    length = arg_to_number(limit)
    length = length if length <= MAX_FILES_LIST else MAX_FILES_LIST

    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)
    page_size = page_size_validness(page_size)

    response = client.get_files_request(length=length,
                                        page_number=page_number,
                                        page_size=page_size,
                                        )

    output_for_hr = arrange_output_for_pcap_file_list_command(response)
    headers = ['node', 'name', 'num', 'first', 'filesize', 'packetsSize']
    mapping = {'node': 'Node',
               'name': 'Name',
               'num': 'Number',
               'first': 'First',
               'filesize': 'File Size',
               'packetsSize': 'Packet Size',
               }
    command_results = CommandResults(
        outputs_prefix='Arkime.PcapFile',
        outputs_key_field='name',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Files List Result:',
                                        output_for_hr,
                                        headerTransform=lambda header: mapping.get(header, header),
                                        headers=headers,
                                        )
    )

    return command_results


def session_list_command(client: Client,
                         date=DEFAULT_DATE,
                         expression=None,
                         start_time=None,
                         stop_time=None,
                         view=None,
                         order=None,
                         fields=None,
                         bounding=None,
                         strictly=None,
                         limit=DEFAULT_LIMIT,
                         page_number=DEFAULT_OFFSET,
                         page_size=DEFAULT_PAGE_SIZE) -> CommandResults:
    date = arg_to_number(date)
    length = arg_to_number(limit)
    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)
    page_size = page_size_validness(page_size)

    response = client.sessions_query_request(date=date,
                                             expression=expression,
                                             start_time=start_time,
                                             stop_time=stop_time,
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
    mapping = {'id': 'ID',
               'ipProtocol': 'IP Protocol',
               'firstPacket': 'First Packet',
               'lastPacket': 'Last Packet',
               'source.ip': 'Source IP',
               'source.port': 'Source Port',
               'destination.ip': 'Destination IP',
               'destination.port': 'Destination Port',
               'node': 'Node'
               }
    command_results = CommandResults(
        outputs_prefix='Arkime.Session',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Session List Result:',
                                        output_for_hr,
                                        headerTransform=lambda header: mapping.get(header, header),
                                        headers=headers,
                                        )
    )

    return command_results


def sessions_csv_get_command(client: Client,
                             date=DEFAULT_DATE,
                             expression=None,
                             start_time=None,
                             stop_time=None,
                             view=None,
                             order=None,
                             fields=None,
                             bounding=None,
                             strictly=None,
                             limit=DEFAULT_LIMIT,
                             offset=DEFAULT_OFFSET) -> Dict:
    date = arg_to_number(date)
    length = arg_to_number(limit)
    start = arg_to_number(offset)

    response = client.sessions_csv_request(date=date,
                                           expression=expression,
                                           start_time=start_time,
                                           stop_time=stop_time,
                                           view=view,
                                           order=order,
                                           fields=fields,
                                           bounding=bounding,
                                           strictly=strictly,
                                           length=length,
                                           start=start,
                                           )

    return fileResult(filename='sessions_list.csv', data=response.content, file_type=EntryType.ENTRY_INFO_FILE)


def sessions_pcap_get_command(client: Client,
                              ids,
                              expression=None,
                              start_time=None,
                              stop_time=None) -> Dict:
    response = client.sessions_pcap_request(ids=ids,
                                            expression=expression,
                                            start_time=start_time,
                                            stop_time=stop_time,
                                            )

    return fileResult(filename='raw_session_data.pcap', data=response.content, file_type=EntryType.ENTRY_INFO_FILE)


def spigraph_get_command(client: Client,
                         field,
                         date=DEFAULT_DATE,
                         expression=None,
                         start_time=None,
                         stop_time=None,
                         view=None,
                         fields=None,
                         bounding=None,
                         strictly=None) -> dict:
    date = arg_to_number(date)

    response = client.spi_graph_request(ids=field,
                                        date=date,
                                        expression=expression,
                                        start_time=start_time,
                                        stop_time=stop_time,
                                        view=view,
                                        fields=fields,
                                        bounding=bounding,
                                        strictly=strictly,
                                        )
    # filter response - omit all keys in json end with Histo
    response = remove_all_keys_endswith_histo(response)

    return fileResult(filename='spi_graph.json', data=str(response), file_type=EntryType.ENTRY_INFO_FILE)


def spiview_get_command(client: Client,
                        spi,
                        date=DEFAULT_DATE,
                        expression=None,
                        start_time=None,
                        stop_time=None,
                        view=None,
                        fields=None,
                        bounding=DEFAULT_BOUNDING,
                        strictly=False) -> dict:
    spi = argToList(spi)
    date = arg_to_number(date)

    response = client.spi_view_request(spi=spi,
                                       date=date,
                                       expression=expression,
                                       start_time=start_time,
                                       stop_time=stop_time,
                                       view=view,
                                       fields=fields,
                                       bounding=bounding,
                                       strictly=strictly,
                                       )

    return fileResult(filename='spi_view.json', data=str(response), file_type=EntryType.ENTRY_INFO_FILE)


def fields_list_command(client: Client,
                        array_response=False,
                        limit=DEFAULT_INTERNAL_LIMIT,
                        page_number=DEFAULT_OFFSET,
                        page_size=DEFAULT_PAGE_SIZE) -> CommandResults:
    limit = arg_to_number(limit)
    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)
    page_size = page_size_validness(page_size)

    response = client.get_fields_request(array_response)
    start = page_size * page_number
    response = response[start:start + limit]

    headers = ['friendlyName', 'type', 'group', 'help', 'dbField']
    mapping = {'friendlyName': 'Friendly Name',
               'type': 'Type',
               'group': 'Group',
               'help': 'Help',
               'dbField': 'DB Field', }
    command_results = CommandResults(
        outputs_prefix='Arkime.Fields',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Fields Results:',
                                        response,
                                        headerTransform=lambda header: mapping.get(header, header),
                                        headers=headers,
                                        )
    )

    return command_results


def unique_field_list_command(client: Client,
                              expression_field_names,
                              counts=DEFAULT_COUNTS,
                              date=DEFAULT_DATE,
                              expression=None,
                              start_time=None,
                              stop_time=None,
                              view=None,
                              order=None,
                              fields=None,
                              bounding=DEFAULT_BOUNDING,
                              strictly=False,
                              limit=DEFAULT_INTERNAL_LIMIT,
                              page_number=DEFAULT_OFFSET,
                              page_size=DEFAULT_PAGE_SIZE
                              ) -> CommandResults:
    counts = arg_to_number(counts)
    date = arg_to_number(date)
    limit = arg_to_number(limit)
    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)
    page_size = page_size_validness(page_size)
    start = page_number * page_size

    response = client.unique_field_request(counts=counts,
                                           expression_field_names=expression_field_names,
                                           date=date,
                                           expression=expression,
                                           start_time=start_time,
                                           stop_time=stop_time,
                                           view=view,
                                           order=order,
                                           fields=fields,
                                           bounding=bounding,
                                           strictly=strictly,
                                           )

    return unique_field_helper(response, start, limit)


def multi_unique_field_list_command(client: Client,
                                    expression_field_names,
                                    counts=DEFAULT_COUNTS,
                                    database_field=None,
                                    date=DEFAULT_DATE,
                                    expression=None,
                                    start_time=None,
                                    stop_time=None,
                                    view=None,
                                    order=None,
                                    fields=None,
                                    bounding=DEFAULT_BOUNDING,
                                    strictly=False,
                                    limit=DEFAULT_INTERNAL_LIMIT,
                                    page_number=DEFAULT_OFFSET,
                                    page_size=DEFAULT_PAGE_SIZE) -> CommandResults:
    date = arg_to_number(date)
    limit = arg_to_number(limit)
    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)
    page_size = page_size_validness(page_size)
    start = page_number * page_size

    response = client.unique_field_multi_request(counts=counts,
                                                 expression_field_names=expression_field_names,
                                                 database_field=database_field,
                                                 date=date,
                                                 expression=expression,
                                                 start_time=start_time,
                                                 stop_time=stop_time,
                                                 view=view,
                                                 order=order,
                                                 fields=fields,
                                                 bounding=bounding,
                                                 strictly=strictly,
                                                 )

    return unique_field_helper(response, start, limit)


def session_tag_add_command(client: Client,
                            tags,
                            session_ids=None,
                            segments=DEFAULT_SEGMENTS,
                            date=DEFAULT_DATE,
                            expression=None,
                            start_time=None,
                            stop_time=None,
                            view=None,
                            order=None,
                            fields=None,
                            bounding=DEFAULT_BOUNDING,
                            strictly=False) -> CommandResults:
    date = arg_to_number(date)

    response = client.add_session_tags_request(tags=tags,
                                               ids=session_ids,
                                               segments=segments,
                                               date=date,
                                               expression=expression,
                                               start_time=start_time,
                                               stop_time=stop_time,
                                               view=view,
                                               order=order,
                                               fields=fields,
                                               bounding=bounding,
                                               strictly=strictly,
                                               )
    headers = ['success', 'text']
    mapping = {'success': 'Success',
               'text': 'Text'
               }
    command_results = CommandResults(
        outputs_prefix='Arkime.Tag',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Session Tag Results:',
                                        response,
                                        headers=headers,
                                        headerTransform=lambda header: mapping.get(header, header),
                                        )
    )

    return command_results


def session_tag_remove_command(client: Client,
                               tags,
                               session_ids=None,
                               segments=DEFAULT_SEGMENTS,
                               date=DEFAULT_DATE,
                               expression=None,
                               start_time=None,
                               stop_time=None,
                               view=None,
                               order=None,
                               fields=None,
                               bounding=DEFAULT_BOUNDING,
                               strictly=False) -> CommandResults:
    date = arg_to_number(date)

    response = client.remove_session_tags_request(tags=tags,
                                                  ids=session_ids,
                                                  segments=segments,
                                                  date=date,
                                                  expression=expression,
                                                  start_time=start_time,
                                                  stop_time=stop_time,
                                                  view=view,
                                                  order=order,
                                                  fields=fields,
                                                  bounding=bounding,
                                                  strictly=strictly,
                                                  )
    headers = ['success', 'text']
    mapping = {
        'success': 'Success',
        'text': 'Text',
    }
    command_results = CommandResults(
        outputs_prefix='Arkime.Tag',
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown('Session Tag Results:',
                                        response,
                                        headers=headers,
                                        headerTransform=lambda header: mapping.get(header, header),
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
            return_results(commands[command](client, **args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
