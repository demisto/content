import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# ----------------------------------------- Imports ---------------------------
import copy
import math
from collections.abc import Callable

from requests import Response

from requests.auth import HTTPDigestAuth
import urllib3

# ----------------------------------------- Constants ---------------------------
PAGE_NUMBER_ERROR_MSG = 'Invalid input Error: page number should be a positive number'
PAGE_SIZE_ERROR_MSG = 'Out Of Range Error: page size should be a positive number between 1-100'
PAGINATION_ERROR_MSG = 'Invalid input Error: one of page size or page number are missing,' \
                       ' need to send both or not send at all'
LENGTH_ERROR_MSG = 'Out Of Range Error: limit/length should be a positive number between 0-{max_length}'
MAX_LENGTH = 2000000
DEFAULT_SEGMENTS = ['no']
DEFAULT_BOUNDING = ['last']
DEFAULT_COUNTS = 0
DEFAULT_DATE = 1
DEFAULT_INTERNAL_LIMIT = 50
DEFAULT_LIMIT = 100
MAX_FILES_LIST = 10000
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
DEFAULT_OFFSET = 0
MAX_BATCH_LIMIT = 500  # is changeable


# ----------------------------------------- Client ---------------------------

class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def connections_csv_request(self,
                                source_field: Optional[str],
                                destination_field: Optional[str],
                                date: int,
                                expression: Optional[str],
                                start_time: Optional[str],
                                stop_time: Optional[str],
                                view: Optional[str],
                                order: Optional[str],
                                fields: Optional[str],
                                bounding: Optional[str],
                                strictly: Optional[bool]):
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
                               )

        headers = self._headers

        response = self._http_request('POST', 'api/connections/csv', params=params, headers=headers,
                                      resp_type='response')

        return response

    def get_connections_request(self,
                                source_field: Optional[str],
                                destination_field: Optional[str],
                                date: int,
                                expression: Optional[str],
                                start_time: Optional[str],
                                stop_time: Optional[str],
                                view: Optional[str],
                                order: Optional[str],
                                fields: Optional[str],
                                bounding: Optional[str],
                                strictly: Optional[bool],
                                baseline_date: Optional[List[str]],
                                baseline_view: Optional[List[str]]):
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
                               )

        headers = self._headers

        response = self._http_request('POST', 'api/connections', params=params, headers=headers)

        return response

    def get_files_request(self,
                          length: int,
                          start: int):
        params = assign_params(length=length, start=start)
        headers = self._headers

        response = self._http_request('GET', 'api/files', params=params, headers=headers)

        return response

    def sessions_query_request(self,
                               date: int,
                               expression: Optional[str],
                               start_time: Optional[str],
                               stop_time: Optional[str],
                               view: Optional[str],
                               order: Optional[str],
                               fields: Optional[str],
                               bounding: Optional[str],
                               strictly: Optional[bool],
                               length: int,
                               start: int):
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

    def sessions_csv_request(self,
                             date: int,
                             expression: Optional[str],
                             start_time: Optional[str],
                             stop_time: Optional[str],
                             view: Optional[str],
                             order: Optional[str],
                             fields: Optional[str],
                             bounding: Optional[str],
                             strictly: Optional[bool],
                             length: int,
                             start: Optional[int]):
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

    def sessions_pcap_request(self,
                              ids: Optional[str],
                              expression: Optional[str],
                              start_time: Optional[str],
                              stop_time: Optional[str]):
        params = assign_params(ids=ids,
                               expression=expression,
                               startTime=start_time,
                               stopTime=stop_time,
                               )

        headers = self._headers

        response = self._http_request('GET', 'api/sessions/pcap', params=params, headers=headers, resp_type='response')

        return response

    def spi_graph_request(self,
                          ids: str,
                          date: int,
                          expression: Optional[str],
                          start_time: Optional[str],
                          stop_time: Optional[str],
                          view: Optional[str],
                          fields: Optional[str],
                          bounding: Optional[List[Any]],
                          strictly: Optional[bool]):
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

    def spi_view_request(self,
                         spi: str,
                         date: int,
                         expression: Optional[str],
                         start_time: Optional[str],
                         stop_time: Optional[str],
                         view: Optional[str],
                         fields: Optional[str],
                         bounding: List,
                         strictly: bool):
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

    def get_fields_request(self,
                           array_response: bool):
        params = assign_params(array=array_response)

        headers = self._headers

        response = self._http_request('GET', 'api/fields', params=params, headers=headers)

        return response

    def unique_field_request(self,
                             counts: int,
                             expression_field_names: str,
                             date: int,
                             expression: Optional[str],
                             start_time: Optional[str],
                             stop_time: Optional[str],
                             view: Optional[str],
                             order: Optional[str],
                             fields: Optional[str],
                             bounding: List[str],
                             strictly: bool):
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

    def unique_field_multi_request(self,
                                   counts: int,
                                   expression_field_names: str,
                                   database_field: Optional[str],
                                   date: int,
                                   expression: Optional[str],
                                   start_time: Optional[str],
                                   stop_time: Optional[str],
                                   view: Optional[str],
                                   order: Optional[str],
                                   fields: Optional[str],
                                   bounding: List[str],
                                   strictly: bool):
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

    def add_session_tags_request(self,
                                 tags: str,
                                 ids: Optional[str],
                                 segments: List[str],
                                 date: int,
                                 expression: Optional[str],
                                 start_time: Optional[str],
                                 stop_time: Optional[str],
                                 view: Optional[str],
                                 order: Optional[str],
                                 fields: Optional[str],
                                 bounding: List[str],
                                 strictly: bool):
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

    def remove_session_tags_request(self,
                                    tags: str,
                                    ids: Optional[str],
                                    segments: List[str],
                                    date: int,
                                    expression: Optional[str],
                                    start_time: Optional[str],
                                    stop_time: Optional[str],
                                    view: Optional[str],
                                    order: Optional[str],
                                    fields: Optional[str],
                                    bounding: List[str],
                                    strictly: bool):
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
    for record in response.get('data', []):
        temp_record = copy.deepcopy(record)
        temp_record['first'] = epochToTimestamp(temp_record['first'])
        output_for_hr.append(temp_record)
    return output_for_hr


def arrange_output_for_session_list_command(response: Dict) -> List:
    headers = ['id', 'ipProtocol', 'source.ip', 'source.port', 'destination.ip', 'destination.port', 'node']

    output_for_hr = []

    for record in response.get('data', []):
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
    if page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)
    return page_size


def page_number_validness(page_number: int) -> int:
    if page_number < 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    return page_number


def length_validness(length: Optional[int], max_length: int) -> int:
    if not length:
        return DEFAULT_LIMIT
    elif length < 0 or length > max_length:
        raise DemistoException(LENGTH_ERROR_MSG.format(max_length=max_length))
    else:
        return length


def remove_all_keys_endswith_histo(response: Dict) -> Dict:
    for key, value in response.copy().items():
        if key.endswith('Histo'):
            del response[key]
        elif isinstance(response[key], dict):
            response[key] = remove_all_keys_endswith_histo(response[key])
        elif isinstance(response[key], List) and len(response[key]) > 0:
            response[key] = [remove_all_keys_endswith_histo(response[key][0])]
    return response


def parse_unique_field_response(text: str) -> List:
    text_lines = text.split('\n')
    unique_field_list_for_hr: list = []
    for line in text_lines:
        spilt_line = line.split(',')
        temp_dic = {'Field': spilt_line[0]}
        if len(spilt_line) > 1:
            temp_dic['Count'] = spilt_line[1]
        unique_field_list_for_hr.append(temp_dic)
    return unique_field_list_for_hr


def unique_field_helper(response: Response, start: int, limit: int, pagination_dict: dict) -> CommandResults:
    headers = ['Field', 'Count']
    unique_field_list = parse_unique_field_response(response.text)
    unique_field_list = unique_field_list[start: start + limit]
    command_results = CommandResults(
        outputs_prefix='Arkime.UniqueField',
        outputs=unique_field_list,
        raw_response=unique_field_list,
        readable_output=create_paging_header(len(unique_field_list), pagination_dict.get('page_number', DEFAULT_OFFSET),
                                             pagination_dict.get('length', DEFAULT_LIMIT),
                                             pagination_dict.get('pagination', False)) + tableToMarkdown(
            'Unique Field Results:', unique_field_list, headers=headers)
    )

    return command_results


def create_paging_header(results_num: int, page_number: int, length: int, pagination: bool) -> str:
    if pagination:
        return f'Showing {results_num} results, limit={length}, from page {page_number}\n'
    return f'Showing {results_num} results, limit={length}\n'


def calculate_offset_and_limit(page_number: int, page_size: int) -> tuple[int, int, int, int]:
    # start / offset == page_number * page_size, and limit is page size
    page_size = page_size_validness(page_size)
    page_number = page_number_validness(page_number)
    start = page_number * page_size  # type: ignore
    return start, page_size, page_number, page_size  # type: ignore


def pagination(page_size: Optional[int], page_number: Optional[int], length: int) -> dict:
    is_pagination = False

    # in pagination case, start/offset == page_number * page_size, length/limit == page_size
    if page_size is not None and page_number is not None:
        start, length, page_number, page_size = calculate_offset_and_limit(page_number, page_size)
        is_pagination = True
        return {'pagination': is_pagination,
                'start': start,
                'length': length,
                'page_number': page_number,
                'page_size': page_size,
                }

    # limit case (without pagination)  start/offset == 0, length/limit == user input or default limit (== 100)
    elif page_size is None and page_number is None:
        return {'start': 0,
                'pagination': is_pagination,
                'length': length,
                }

    # pagination case, but given only page_number or page_size - so in this case we throw an exception
    else:
        raise DemistoException(PAGINATION_ERROR_MSG)


def union(dict1: dict, dict2: dict) -> dict:
    """
    When the limit is bigger than MAX_BATCH_LIMIT, to avoid timeout, we perform some api calls and chain the responses
    together into one dictionary by this function.
    """
    res = {}
    for key in dict2:
        if not dict1.get(key):
            res[key] = dict2.get(key)
        elif isinstance(dict2.get(key), dict):
            res[key] = {**dict1.get(key), **dict2.get(key)}  # type: ignore
        else:
            res[key] = dict1.get(key) + dict2.get(key)  # type: ignore
    return res


def responses_by_batches(request_method: Callable, length: int, start: int, **kwargs) -> Dict:
    num_of_batches = math.ceil(length / MAX_BATCH_LIMIT)
    temp_length = MAX_BATCH_LIMIT
    temp_start = start
    final_response: Dict[str, Any] = {}
    for i in range(num_of_batches):
        response = request_method(length=temp_length,
                                  start=temp_start,
                                  **kwargs)
        final_response = union(final_response, response)
        temp_start += temp_length  # update the offset after every batch
        length -= temp_length
        temp_length = MAX_BATCH_LIMIT if length > MAX_BATCH_LIMIT else length  # update the length after every batch

    return final_response


# ----------------------------------------- Command functions ---------------------------


def connection_csv_get_command(client: Client,
                               source_field: str = None,
                               destination_field: str = None,
                               date: int = DEFAULT_DATE,
                               expression: str = None,
                               start_time: str = None,
                               stop_time: str = None,
                               view: str = None,
                               order: str = None,
                               fields: str = None,
                               bounding: str = None,
                               strictly: bool = None) -> Dict:
    """
    Gets a list of nodes and links in csv format and returns them to the client.
    """

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
                                              )

    return fileResult(filename='connections_list.csv', data=response.content, file_type=EntryType.ENTRY_INFO_FILE)


def connection_list_command(client: Client,
                            source_field: str = None,
                            destination_field: str = None,
                            date: int = DEFAULT_DATE,
                            expression: str = None,
                            start_time: str = None,
                            stop_time: str = None,
                            view: str = None,
                            order: str = None,
                            fields: str = None,
                            bounding: str = None,
                            strictly: bool = None,
                            baseline_date: List[str] = None,
                            baseline_view: List[str] = None
                            ) -> CommandResults:
    """
    Gets a list of nodes and links and returns them to the client.
    """
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
                                        headerTransform=lambda
                                        header: mapping.get(header, header),
                                        headers=headers)
    )

    return command_results


def pcap_file_list_command(client: Client,
                           limit: int = 500,
                           page_number: int = None,
                           page_size: int = None) -> CommandResults:
    """
    Gets a list of PCAP files that Arkime knows about.
    """
    length = length_validness(arg_to_number(limit), MAX_FILES_LIST)

    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)

    pagination_dict = pagination(page_size, page_number, length)

    start = pagination_dict.get('page_number', DEFAULT_OFFSET)
    length = pagination_dict.get('length', DEFAULT_LIMIT)
    is_pagination: bool = pagination_dict.get('pagination', False)  # type: ignore

    # To avoid time out, we do api calls by batches
    if not is_pagination and length > MAX_BATCH_LIMIT:
        response = responses_by_batches(client.get_files_request, length=length, start=start)
    else:
        response = client.get_files_request(length=length, start=start)

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
        readable_output=create_paging_header(len(output_for_hr), start, length, is_pagination) + tableToMarkdown(
            'Files List Result:', output_for_hr, headerTransform=lambda header: mapping.get(header, header),
            headers=headers)
    )

    return command_results


def session_list_command(client: Client,
                         date: int = DEFAULT_DATE,
                         expression: str = None,
                         start_time: str = None,
                         stop_time: str = None,
                         view: str = None,
                         order: str = None,
                         fields: str = None,
                         bounding: str = None,
                         strictly: bool = None,
                         limit: int = DEFAULT_LIMIT,
                         page_number: int = None,
                         page_size: int = None) -> CommandResults:
    length = length_validness(arg_to_number(limit), MAX_LENGTH)
    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)

    pagination_dict = pagination(page_size, page_number, length)
    length: int = pagination_dict.get('length', DEFAULT_LIMIT)
    start: int = pagination_dict.get('start', DEFAULT_OFFSET)
    is_pagination: bool = pagination_dict.get('pagination', False)  # type: ignore

    # To avoid time out, we do api calls by batches
    if not pagination_dict.get('pagination', False) and pagination_dict.get('length', DEFAULT_LIMIT) > MAX_BATCH_LIMIT:
        response = responses_by_batches(client.sessions_query_request,
                                        length=length,
                                        start=start,
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
    else:
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
                                                 start=start,
                                                 )

    output_for_hr = arrange_output_for_session_list_command(response)
    headers = ['id', 'ipProtocol', 'firstPacket', 'lastPacket', 'source.ip', 'source.port', 'destination.ip',
               'destination.port', 'node']
    mapping = {'id': 'ID',
               'ipProtocol': 'IP Protocol',
               'firstPacket': 'Start Time',
               'lastPacket': 'Stop Time',
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
        readable_output=create_paging_header(len(output_for_hr), start, length, is_pagination) + tableToMarkdown(
            'Session List Result:', output_for_hr, headerTransform=lambda header: mapping.get(header, header),
            headers=headers)
    )

    return command_results


def sessions_csv_get_command(client: Client,
                             date: int = DEFAULT_DATE,
                             expression: str = None,
                             start_time: str = None,
                             stop_time: str = None,
                             view: str = None,
                             order: str = None,
                             fields: str = None,
                             bounding: str = None,
                             strictly: bool = None,
                             limit: int = DEFAULT_LIMIT,
                             offset: int = DEFAULT_OFFSET) -> Dict:
    length = length_validness(arg_to_number(limit), MAX_LENGTH)
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
                              ids: str = None,
                              expression: str = None,
                              start_time: str = None,
                              stop_time: str = None) -> Dict:
    response = client.sessions_pcap_request(ids=ids,
                                            expression=expression,
                                            start_time=start_time,
                                            stop_time=stop_time,
                                            )

    return fileResult(filename='raw_session_data.pcap', data=response.content, file_type=EntryType.ENTRY_INFO_FILE)


def spigraph_get_command(client: Client,
                         field: str,
                         date: int = DEFAULT_DATE,
                         expression: str = None,
                         start_time: str = None,
                         stop_time: str = None,
                         view: str = None,
                         fields: str = None,
                         bounding: List = None,
                         strictly: bool = None) -> dict:
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
                        spi: str,
                        date: int = DEFAULT_DATE,
                        expression: str = None,
                        start_time: str = None,
                        stop_time: str = None,
                        view: str = None,
                        fields: str = None,
                        bounding: List = DEFAULT_BOUNDING,
                        strictly: bool = False) -> dict:
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
                        array_response: bool = False) -> CommandResults:
    response = client.get_fields_request(array_response)

    headers = ['friendlyName', 'type', 'group', 'help', 'dbField']
    mapping = {'friendlyName': 'Friendly Name',
               'type': 'Type',
               'group': 'Group',
               'help': 'Help',
               'dbField': 'DB Field', }
    command_results = CommandResults(
        outputs_prefix='Arkime.Field',
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
                              expression_field_names: str,
                              counts: int = DEFAULT_COUNTS,
                              date: int = DEFAULT_DATE,
                              expression: str = None,
                              start_time: str = None,
                              stop_time: str = None,
                              view: str = None,
                              order: str = None,
                              fields: str = None,
                              bounding: List[str] = DEFAULT_BOUNDING,
                              strictly: bool = False,
                              limit: int = DEFAULT_INTERNAL_LIMIT,
                              page_number: int = None,
                              page_size: int = None,
                              ) -> CommandResults:
    limit = length_validness(arg_to_number(limit), MAX_LENGTH)
    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)

    pagination_dict = pagination(page_size, page_number, limit)

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

    return unique_field_helper(response, pagination_dict.get('start', DEFAULT_OFFSET),
                               pagination_dict.get('length', DEFAULT_LIMIT), pagination_dict)


def multi_unique_field_list_command(client: Client,
                                    expression_field_names: str,
                                    counts: int = DEFAULT_COUNTS,
                                    database_field: str = None,
                                    date: int = DEFAULT_DATE,
                                    expression: str = None,
                                    start_time: str = None,
                                    stop_time: str = None,
                                    view: str = None,
                                    order: str = None,
                                    fields: str = None,
                                    bounding: List[str] = DEFAULT_BOUNDING,
                                    strictly: bool = False,
                                    limit: int = DEFAULT_INTERNAL_LIMIT,
                                    page_number: int = None,
                                    page_size: int = None) -> CommandResults:
    limit = length_validness(arg_to_number(limit), MAX_LENGTH)
    page_number = arg_to_number(page_number)
    page_size = arg_to_number(page_size)

    pagination_dict = pagination(page_size, page_number, limit)

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

    return unique_field_helper(response, pagination_dict.get('start', DEFAULT_OFFSET),
                               pagination_dict.get('length', DEFAULT_LIMIT), pagination_dict)


def session_tag_add_command(client: Client,
                            tags: str,
                            session_ids: str = None,
                            segments: List[str] = DEFAULT_SEGMENTS,
                            date: int = DEFAULT_DATE,
                            expression: str = None,
                            start_time: str = None,
                            stop_time: str = None,
                            view: str = None,
                            order: str = None,
                            fields: str = None,
                            bounding: List[str] = DEFAULT_BOUNDING,
                            strictly: bool = False) -> CommandResults:
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
                               tags: str,
                               session_ids: str = None,
                               segments: List[str] = DEFAULT_SEGMENTS,
                               date: int = DEFAULT_DATE,
                               expression: str = None,
                               start_time: str = None,
                               stop_time: str = None,
                               view: str = None,
                               order: str = None,
                               fields: str = None,
                               bounding: List[str] = DEFAULT_BOUNDING,
                               strictly: bool = False) -> CommandResults:
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
    message: str = ''
    try:
        if connection_list_command(client=client):
            message = 'ok'
    except DemistoException as e:
        if 'Unauthorized' in str(e):
            message = 'Authorization Error: make sure username and password are correctly set'
        else:
            raise e
    return return_results(message)


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    auth = HTTPDigestAuth(demisto.get(params, 'credentials.identifier'), demisto.get(params, 'credentials.password'))
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {'Content-Type': 'application/json'}

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=auth)

        commands: Dict[str, Callable] = {
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
