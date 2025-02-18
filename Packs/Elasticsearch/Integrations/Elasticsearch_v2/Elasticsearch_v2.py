import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

from CommonServerUserPython import *

'''IMPORTS'''
from datetime import datetime
import json
import requests
import warnings
from dateutil.parser import parse
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()
warnings.filterwarnings(action="ignore", message='.*using SSL with verify_certs=False is insecure.')

ELASTICSEARCH_V8 = 'Elasticsearch_v8'
OPEN_SEARCH = 'OpenSearch'
ELASTIC_SEARCH_CLIENT = demisto.params().get('client_type')
if ELASTIC_SEARCH_CLIENT == OPEN_SEARCH:
    from opensearchpy import OpenSearch as Elasticsearch, RequestsHttpConnection, NotFoundError
    from opensearch_dsl import Search
    from opensearch_dsl.query import QueryString
elif ELASTIC_SEARCH_CLIENT == ELASTICSEARCH_V8:
    from elasticsearch import Elasticsearch, NotFoundError  # type: ignore[assignment]
    from elasticsearch_dsl import Search
    from elasticsearch_dsl.query import QueryString
    from elastic_transport import RequestsHttpNode
else:  # Elasticsearch (<= v7)
    from elasticsearch7 import Elasticsearch, RequestsHttpConnection, NotFoundError  # type: ignore[assignment]
    from elasticsearch_dsl import Search
    from elasticsearch_dsl.query import QueryString


ES_DEFAULT_DATETIME_FORMAT = 'yyyy-MM-dd HH:mm:ss.SSSSSS'
PYTHON_DEFAULT_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'
API_KEY_PREFIX = '_api_key_id:'
SERVER = demisto.params().get('url', '').rstrip('/')
USERNAME: str = demisto.params().get('credentials', {}).get('identifier')
PASSWORD: str = demisto.params().get('credentials', {}).get('password')
API_KEY_ID = USERNAME[len(API_KEY_PREFIX):] if USERNAME and USERNAME.startswith(API_KEY_PREFIX) else None
if API_KEY_ID:
    USERNAME = ""
    API_KEY = (API_KEY_ID, PASSWORD)
PROXY = demisto.params().get('proxy')
HTTP_ERRORS = {
    400: '400 Bad Request - Incorrect or invalid parameters',
    401: '401 Unauthorized - Incorrect or invalid username or password',
    403: '403 Forbidden - The account does not support performing this task',
    404: '404 Not Found - Elasticsearch server was not found',
    408: '408 Timeout - Check port number or Elasticsearch server credentials',
    410: '410 Gone - Elasticsearch server no longer exists in the service',
    500: '500 Internal Server Error - Internal error',
    503: '503 Service Unavailable'
}

'''VARIABLES FOR FETCH INCIDENTS'''
param = demisto.params()
TIME_FIELD = param.get('fetch_time_field', '')
FETCH_INDEX = param.get('fetch_index', '')
FETCH_QUERY_PARM = param.get('fetch_query', '')
RAW_QUERY = param.get('raw_query', '')
FETCH_TIME = param.get('fetch_time', '3 days')
FETCH_SIZE = int(param.get('fetch_size', 50))
INSECURE = not param.get('insecure', False)
TIME_METHOD = param.get('time_method', 'Simple-Date')
TIMEOUT = int(param.get('timeout') or 60)
MAP_LABELS = param.get('map_labels', True)

FETCH_QUERY = RAW_QUERY or FETCH_QUERY_PARM


def get_value_by_dot_notation(dictionary, key):
    """
    Get dictionary value by key using dot notation.

    Args:
        dictionary (dict): The dictionary to search within.
        key (str): The key in dot notation.

    Returns:
        The value corresponding to the key if found, otherwise None.
    """
    value = dictionary
    demisto.debug('Trying to get value by dot notation')
    for k in key.split('.'):
        if isinstance(value, dict):
            value = value.get(k)
        else:
            demisto.debug(f'Last value is not a dict, returning None. {value=}')
            return None
    return value


def convert_date_to_timestamp(date):
    """converts datetime to the relevant timestamp format.

    Args:
        date(datetime): A datetime object setting up the last fetch time

    Returns:
        (num | str): The formatted timestamp
    """
    # this theoretically shouldn't happen but just in case
    if str(date).isdigit():
        return int(date)

    if TIME_METHOD == 'Timestamp-Seconds':
        return int(date.timestamp())

    if TIME_METHOD == 'Timestamp-Milliseconds':
        return int(date.timestamp() * 1000)

    # In case of 'Simple-Date'.
    return datetime.strftime(date, PYTHON_DEFAULT_DATETIME_FORMAT)


def timestamp_to_date(timestamp_string):
    """Converts a timestamp string to a datetime object.

    Args:
        timestamp_string(string): A string with a timestamp in it.

    Returns:
        (datetime).represented by the timestamp in the format '%Y-%m-%d %H:%M:%S.%f'
    """
    timestamp_number: float
    # find timestamp in form of more than seconds since epoch: 1572164838000
    if TIME_METHOD == 'Timestamp-Milliseconds':
        timestamp_number = float(int(timestamp_string) / 1000)

    # find timestamp in form of seconds since epoch: 1572164838
    else:  # TIME_METHOD == 'Timestamp-Seconds':
        demisto.debug(f"{TIME_METHOD=}. Should be Timestamp-Seconds.")
        timestamp_number = float(timestamp_string)

    # convert timestamp (a floating point number representing time since epoch) to datetime
    return datetime.utcfromtimestamp(timestamp_number)


def get_api_key_header_val(api_key):
    """
    Check the type of the passed api_key and return the correct header value
    for the `API Key authentication
    <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html>`
    :arg api_key, either a tuple or a base64 encoded string
    """
    if isinstance(api_key, tuple | list):
        s = f"{api_key[0]}:{api_key[1]}".encode()
        return "ApiKey " + base64.b64encode(s).decode('utf-8')
    return "ApiKey " + api_key


def elasticsearch_builder(proxies):
    """Builds an Elasticsearch obj with the necessary credentials, proxy settings and secure connection."""

    connection_args: Dict[str, Union[bool, int, str, list, tuple[str, str], RequestsHttpConnection]] = {
        "hosts": [SERVER],
        "verify_certs": INSECURE,
        "timeout": TIMEOUT,
    }
    if ELASTIC_SEARCH_CLIENT != ELASTICSEARCH_V8:
        # Adding the proxy related parameters to the Elasticsearch client v7 and below or OpenSearch (BC)
        connection_args["connection_class"] = RequestsHttpConnection  # type: ignore[assignment]
        connection_args["proxies"] = proxies

    else:
        # Adding the proxy related parameter to the Elasticsearch client v8
        # Reference- https://github.com/elastic/elastic-transport-python/issues/53#issuecomment-1447903214
        class CustomHttpNode(RequestsHttpNode):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.session.proxies = proxies
        connection_args['node_class'] = CustomHttpNode  # type: ignore[assignment]

    if API_KEY_ID:
        connection_args["api_key"] = API_KEY

    elif USERNAME:
        if ELASTIC_SEARCH_CLIENT == ELASTICSEARCH_V8:
            connection_args["basic_auth"] = (USERNAME, PASSWORD)
        else:  # Elasticsearch version v7 and below or OpenSearch (BC)
            connection_args["http_auth"] = (USERNAME, PASSWORD)

    es = Elasticsearch(**connection_args)  # type: ignore[arg-type]
    # this should be passed as api_key via Elasticsearch init, but this code ensures it'll be set correctly
    if API_KEY_ID and hasattr(es, 'transport'):
        es.transport.get_connection().session.headers['authorization'] = get_api_key_header_val(  # type: ignore[attr-defined]
            API_KEY)

    return es


def get_hit_table(hit):
    """Create context for a single hit in the search.

    Args:
        hit(Dict): a dictionary representing a single hit in the search.

    Returns:
        (dict).The hit context.
        (list).the headers of the hit.
    """
    table_context = {
        '_index': hit.get('_index'),
        '_id': hit.get('_id'),
        '_type': hit.get('_type'),
        '_score': hit.get('_score'),
    }
    headers = ['_index', '_id', '_type', '_score']
    if hit.get('_source') is not None:
        for source_field in hit.get('_source'):
            table_context[str(source_field)] = hit.get('_source').get(str(source_field))
            headers.append(source_field)

    return table_context, headers


def results_to_context(index, query, base_page, size, total_dict, response, event=False):
    """Creates context for the full results of a search.

    Args:
        index(str): the index in which the search was made.
        query(str): the query of the search.
        base_page(int): the base page from which the search is made.
        size(int): the amount of results to return.
        total_dict(dict): a dictionary containing the info about thenumber of total results found
        response(Dict): the raw response of the results.

    Returns:
        (dict).The full context for the search results.
        (list).The metadata headers of the search.
        (list).the context for the hits.
        (list).the headers of the hits.
    """
    search_context = {
        'Server': SERVER,
        'Index': index,
        'Query': query,
        'Page': base_page,
        'Size': size,
        'total': total_dict,
        'max_score': response.get('hits').get('max_score'),
        'took': response.get('took'),
        'timed_out': response.get('timed_out')
    }

    if aggregations := response.get('aggregations'):
        search_context['aggregations'] = aggregations

    hit_headers = []  # type: List
    hit_tables = []
    if total_dict.get('value') > 0:
        if not event:
            results = response.get('hits').get('hits', [])
        else:
            results = response.get('hits').get('events', [])

        for hit in results:
            single_hit_table, single_header = get_hit_table(hit)
            hit_tables.append(single_hit_table)
            hit_headers = list(set(single_header + hit_headers) - {'_id', '_type', '_index', '_score'})
        hit_headers = ['_id', '_index', '_type', '_score'] + hit_headers

    search_context['Results'] = response.get('hits').get('hits')
    meta_headers = ['Query', 'took', 'timed_out', 'total', 'max_score', 'Server', 'Page', 'Size', 'aggregations']
    return search_context, meta_headers, hit_tables, hit_headers


def get_total_results(response_dict):
    """Creates a dictionary with all for the number of total results found

    Args:
        response_dict(dict): the raw response from elastic search.

    Returns:
        (dict).The total results info for the context.
        (num).The number of total results.
    """
    total_results = response_dict.get('hits', {}).get('total')
    if not str(total_results).isdigit():
        # if in version 7 - total number of hits has value field
        total_results = total_results.get('value')
        total_dict = response_dict.get('hits').get('total')

    else:
        total_dict = {
            'value': total_results,
        }

    return total_dict, total_results


def search_command(proxies):
    """Performs a search in Elasticsearch."""
    index = demisto.args().get('index')
    query = demisto.args().get('query')
    fields = demisto.args().get('fields')  # fields to display
    explain = demisto.args().get('explain', 'false').lower() == 'true'
    base_page = int(demisto.args().get('page'))
    size = int(demisto.args().get('size'))
    sort_field = demisto.args().get('sort-field')
    sort_order = demisto.args().get('sort-order')
    query_dsl = demisto.args().get('query_dsl')
    timestamp_field = demisto.args().get('timestamp_field')
    timestamp_range_start = demisto.args().get('timestamp_range_start')
    timestamp_range_end = demisto.args().get('timestamp_range_end')

    if query and query_dsl:
        return_error("Both query and query_dsl are configured. Please choose between query or query_dsl.")

    es = elasticsearch_builder(proxies)
    time_range_dict = None
    if timestamp_range_end or timestamp_range_start:
        time_range_dict = get_time_range(time_range_start=timestamp_range_start, time_range_end=timestamp_range_end,
                                         time_field=timestamp_field,
                                         )

    if query_dsl:
        response = execute_raw_query(es, query_dsl, index, size, base_page)

    else:
        que = QueryString(query=query)
        search = Search(using=es, index=index).query(que)[base_page:base_page + size]
        if explain:
            # if 'explain parameter is set to 'true' - adds explanation section to search results
            search = search.extra(explain=True)

        if time_range_dict:
            search = search.filter(time_range_dict)

        if fields is not None:
            fields = fields.split(',')
            search = search.source(fields)

        if sort_field is not None:
            search = search.sort({sort_field: {'order': sort_order}})

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

    total_dict, total_results = get_total_results(response)
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(index, query_dsl or query, base_page,
                                                                               size, total_dict, response)
    search_human_readable = tableToMarkdown('Search Metadata:', search_context, meta_headers, removeNull=True)
    hits_human_readable = tableToMarkdown('Hits:', hit_tables, hit_headers, removeNull=True)
    total_human_readable = search_human_readable + '\n' + hits_human_readable
    full_context = {
        'Elasticsearch.Search(val.Query == obj.Query && val.Index == obj.Index '
        '&& val.Server == obj.Server && val.Page == obj.Page && val.Size == obj.Size)': search_context
    }

    return_outputs(total_human_readable, full_context, response)


def fetch_params_check():
    """If is_fetch is ticked, this function checks that all the necessary parameters for the fetch are entered."""
    str_error = []  # type:List
    if (TIME_FIELD == '' or TIME_FIELD is None) and not RAW_QUERY:
        str_error.append("Index time field is not configured.")

    if not FETCH_QUERY:
        str_error.append("Query by which to fetch incidents is not configured.")

    if RAW_QUERY and FETCH_QUERY_PARM:
        str_error.append("Both Query and Raw Query are configured. Please choose between Query or Raw Query.")

    if len(str_error) > 0:
        return_error("Got the following errors in test:\nFetches incidents is enabled.\n" + '\n'.join(str_error))


def test_query_to_fetch_incident_index(es):
    """Test executing query in fetch index.

    Notes:
        if is_fetch it ticked, this function runs a general query to Elasticsearch just to make sure we get a response
        from the FETCH_INDEX.

    Args:
        es(Elasticsearch): an Elasticsearch object to which we run the test.
    """
    try:
        query = QueryString(query='*')
        search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]

        if ELASTIC_SEARCH_CLIENT == ELASTICSEARCH_V8:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below or OpenSearch
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

        _, total_results = get_total_results(response)

    except NotFoundError as e:
        return_error("Fetch incidents test failed.\nError message: {}.".format(str(e).split(',')[2][2:-1]))


def test_general_query(es):
    """Test executing query to all available indexes.

    Args:
        es(Elasticsearch): an Elasticsearch object to which we run the test.
    """
    try:
        query = QueryString(query='*')
        search = Search(using=es, index='*').query(query)[0:1]

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

        get_total_results(response)

    except NotFoundError as e:
        return_error(f"Failed executing general search command - please check the Server URL and port number "
                     f"and the supplied credentials.\nError message: {str(e)}.")


def test_time_field_query(es):
    """Test executing query of fetch time field.

    Notes:
        if is_fetch is ticked, this function checks if the entered TIME_FIELD returns results.

    Args:
        es(Elasticsearch): an Elasticsearch object to which we run the test.

    Returns:
        (dict).The results of the query if they are returned.
    """
    query = QueryString(query=TIME_FIELD + ':*')
    search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, OPEN_SEARCH]:
        response = search.execute().to_dict()

    else:  # Elasticsearch v7 and below
        # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
        response = es.search(index=search._index, body=search.to_dict(), **search._params)

    _, total_results = get_total_results(response)

    if total_results == 0:
        # failed in getting the TIME_FIELD
        raise Exception(f"Fetch incidents test failed.\nDate field value incorrect [{TIME_FIELD}].")

    else:
        return response


def test_fetch_query(es):
    """Test executing fetch query.

    Notes:
        if is_fetch is ticked, this function checks if the FETCH_QUERY returns results.

    Args:
        es(Elasticsearch): an Elasticsearch object to which we run the test.

    Returns:
        (dict).The results of the query if they are returned.
    """
    query = QueryString(query=str(TIME_FIELD) + ":* AND " + FETCH_QUERY)
    search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, OPEN_SEARCH]:
        response = search.execute().to_dict()

    else:  # Elasticsearch v7 and below
        # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
        response = es.search(index=search._index, body=search.to_dict(), **search._params)

    _, total_results = get_total_results(response)

    if total_results > 0:
        return response

    else:
        # failed to get the TIME_FIELD with the FETCH_QUERY
        # this can happen and not be an error if the FETCH_QUERY doesn't have results yet.
        # Thus this does not return an error message
        return None


def test_timestamp_format(timestamp):
    """if is_fetch is ticked and the TIME_METHOD chosen is a type of timestamp - this function checks that
        the timestamp is in the correct format.

    Args:
        timestamp(sting): a timestamp string.
    """
    timestamp_in_seconds_len = len(str(int(time.time())))

    if TIME_METHOD == 'Timestamp-Seconds':
        if not timestamp.isdigit():
            return_error(f"The time field does not contain a standard timestamp.\nFetched: {timestamp}")

        elif len(timestamp) > timestamp_in_seconds_len:
            return_error(f"Fetched timestamp is not in seconds since epoch.\nFetched: {timestamp}")

    elif TIME_METHOD == 'Timestamp-Milliseconds':
        if not timestamp.isdigit():
            return_error(f"The timestamp fetched is not in milliseconds.\nFetched: {timestamp}")

        elif len(timestamp) <= timestamp_in_seconds_len:
            return_error(f"Fetched timestamp is not in milliseconds since epoch.\nFetched: {timestamp}")


def test_connectivity_auth(proxies):
    headers = {
        'Content-Type': "application/json"
    }
    if API_KEY_ID:
        headers['authorization'] = get_api_key_header_val(API_KEY)

    try:
        if USERNAME:
            res = requests.get(SERVER, auth=(USERNAME, PASSWORD), verify=INSECURE, headers=headers)

        else:
            res = requests.get(SERVER, verify=INSECURE, headers=headers)

        if res.status_code >= 400:
            try:
                res.raise_for_status()

            except requests.exceptions.HTTPError as e:
                if HTTP_ERRORS.get(res.status_code) is not None:
                    # if it is a known http error - get the message form the preset messages
                    return_error("Failed to connect. "
                                 f"The following error occurred: {HTTP_ERRORS.get(res.status_code)}")

                else:
                    # if it is unknown error - get the message from the error itself
                    return_error(f"Failed to connect. The following error occurred: {e}")

        elif res.status_code == 200:
            verify_es_server_version(res.json())

    except requests.exceptions.RequestException as e:
        return_error("Failed to connect. Check Server URL field and port number.\nError message: " + str(e))


def verify_es_server_version(res):
    """
    Gets the requests.get raw response, extracts the elasticsearch server version,
    and verifies that the client type parameter is configured accordingly.
    Raises exceptions for server version miss configuration issues.

    Args:
        res(dict): requests.models.Response object including information regarding the elasticsearch server.
    """
    es_server_version = res.get('version', {}).get('number', '')
    demisto.debug(f"Elasticsearch server version is: {es_server_version}")
    if es_server_version:
        major_version = es_server_version.split('.')[0]
        if major_version:
            if int(major_version) >= 8 and ELASTIC_SEARCH_CLIENT not in [ELASTICSEARCH_V8, OPEN_SEARCH]:
                raise ValueError(f'Configuration Error: Your Elasticsearch server is version {es_server_version}. '
                                 f'Please ensure that the client type is set to {ELASTICSEARCH_V8} or {OPEN_SEARCH}. '
                                 f'For more information please see the integration documentation.')
            elif int(major_version) <= 7 and ELASTIC_SEARCH_CLIENT not in [OPEN_SEARCH, 'Elasticsearch']:
                raise ValueError(f'Configuration Error: Your Elasticsearch server is version {es_server_version}. '
                                 f'Please ensure that the client type is set to Elasticsearch or {OPEN_SEARCH}. '
                                 f'For more information please see the integration documentation.')


def test_func(proxies):
    """
      Tests API connectivity to the Elasticsearch server.
      Tests the existence of all necessary fields for fetch.

      Due to load considerations, the test module doesn't check the validity of the fetch-incident - to test that the fetch works
      as excepted the user should run the es-integration-health-check command.

    """
    test_connectivity_auth(proxies)
    if demisto.params().get('isFetch'):
        # check the existence of all necessary fields for fetch
        fetch_params_check()
    demisto.results('ok')


def integration_health_check(proxies):
    test_connectivity_auth(proxies)
    # build general Elasticsearch class
    es = elasticsearch_builder(proxies)

    if demisto.params().get('isFetch'):
        # check the existence of all necessary fields for fetch
        fetch_params_check()

        try:

            # test if FETCH_INDEX exists
            test_query_to_fetch_incident_index(es)

            # test if TIME_FIELD in index exists
            response = test_time_field_query(es)

            # try to get response from FETCH_QUERY - if exists check the time field from that query
            if RAW_QUERY:
                raw_query = RAW_QUERY
                try:
                    raw_query = json.loads(raw_query)
                except Exception as e:
                    demisto.info(f"unable to convert raw query to dictionary, use it as a string\n{e}")

                temp = es.search(index=FETCH_INDEX, body={"query": raw_query})
            else:
                temp = test_fetch_query(es)

            if temp:
                response = temp

            # get the value in the time field
            source = response.get('hits', {}).get('hits')[0].get('_source', {})
            hit_date = str(get_value_by_dot_notation(source, str(TIME_FIELD)))

            # if not a timestamp test the conversion to datetime object
            if 'Timestamp' not in TIME_METHOD:
                parse(str(hit_date))

            # test timestamp format and conversion to date
            else:
                test_timestamp_format(hit_date)
                timestamp_to_date(hit_date)

        except ValueError as e:
            return_error("Inserted time format is incorrect.\n" + str(e) + '\n' + TIME_FIELD + ' fetched: ' + hit_date)

    else:
        # check that we can reach any indexes in the supplied server URL
        test_general_query(es)
    return "Testing was successful."


def incident_label_maker(source):
    """Creates labels for the created incident.

    Args:
        source(dict): the _source fields of a hit.

    Returns:
        (list).The labels.
    """
    labels = []
    for field, value in source.items():
        encoded_value = value if isinstance(value, str) else json.dumps(value)
        labels.append({'type': str(field), 'value': encoded_value})

    return labels


def results_to_incidents_timestamp(response, last_fetch):
    """Converts the current results into incidents.

    Args:
        response(dict): the raw search results from Elasticsearch.
        last_fetch(num): the date or timestamp of the last fetch before this fetch
        - this will hold the last date of the incident brought by this fetch.

    Returns:
        (list).The incidents.
        (num).The date of the last incident brought by this fetch.
    """
    current_fetch = last_fetch
    incidents = []
    for hit in response.get('hits', {}).get('hits'):
        source = hit.get('_source')
        if source is not None:
            time_field_value = get_value_by_dot_notation(source, str(TIME_FIELD))

            if time_field_value is not None:
                # if timestamp convert to iso format date and save the timestamp
                hit_date = timestamp_to_date(str(time_field_value))
                hit_timestamp = int(time_field_value)

                if hit_timestamp > last_fetch:
                    last_fetch = hit_timestamp

                # avoid duplication due to weak time query
                if hit_timestamp > current_fetch:
                    inc = {
                        'name': 'Elasticsearch: Index: ' + str(hit.get('_index')) + ", ID: " + str(hit.get('_id')),
                        'rawJSON': json.dumps(hit),
                        'occurred': hit_date.isoformat() + 'Z',
                    }
                    if hit.get('_id'):
                        inc['dbotMirrorId'] = hit.get('_id')

                    if MAP_LABELS:
                        inc['labels'] = incident_label_maker(hit.get('_source'))

                    incidents.append(inc)

    return incidents, last_fetch


def results_to_incidents_datetime(response, last_fetch):
    """Converts the current results into incidents.

    Args:
        response(dict): the raw search results from Elasticsearch.
        last_fetch(datetime): the date or timestamp of the last fetch before this fetch or parameter default fetch time
        - this will hold the last date of the incident brought by this fetch.

    Returns:
        (list).The incidents.
        (datetime).The date of the last incident brought by this fetch.
    """
    last_fetch = dateparser.parse(last_fetch)
    last_fetch_timestamp = int(last_fetch.timestamp() * 1000)  # type:ignore[union-attr]
    current_fetch = last_fetch_timestamp
    incidents = []

    for hit in response.get('hits', {}).get('hits'):
        source = hit.get('_source')
        if source is not None:
            time_field_value = get_value_by_dot_notation(source, str(TIME_FIELD))
            if time_field_value is not None:
                hit_date = parse(str(time_field_value))
                hit_timestamp = int(hit_date.timestamp() * 1000)

                if hit_timestamp > last_fetch_timestamp:
                    last_fetch = hit_date
                    last_fetch_timestamp = hit_timestamp

                # avoid duplication due to weak time query
                if hit_timestamp > current_fetch:
                    inc = {
                        'name': 'Elasticsearch: Index: ' + str(hit.get('_index')) + ", ID: " + str(hit.get('_id')),
                        'rawJSON': json.dumps(hit),
                        # parse function returns iso format sometimes as YYYY-MM-DDThh:mm:ss+00:00
                        # and sometimes as YYYY-MM-DDThh:mm:ss
                        # we want to return format: YYYY-MM-DDThh:mm:ssZ in our incidents
                        'occurred': format_to_iso(hit_date.isoformat()),
                    }
                    if hit.get('_id'):
                        inc['dbotMirrorId'] = hit.get('_id')

                    if MAP_LABELS:
                        inc['labels'] = incident_label_maker(hit.get('_source'))

                    incidents.append(inc)

    return incidents, last_fetch.isoformat()  # type:ignore[union-attr]


def format_to_iso(date_string):
    """Formatting function to make sure the date string is in YYYY-MM-DDThh:mm:ssZ format.

    Args:
        date_string(str): a date string in ISO format could be like: YYYY-MM-DDThh:mm:ss+00:00 or: YYYY-MM-DDThh:mm:ss

    Returns:
        str. A date string in the format: YYYY-MM-DDThh:mm:ssZ
    """
    if '.' in date_string:
        date_string = date_string.split('.')[0]

    if len(date_string) > 19 and not date_string.endswith('Z'):
        date_string = date_string[:-6]

    if not date_string.endswith('Z'):
        date_string = date_string + 'Z'

    return date_string


def get_time_range(last_fetch: Union[str, None] = None, time_range_start=FETCH_TIME,
                   time_range_end=None, time_field=TIME_FIELD) -> Dict:
    """
    Creates the time range filter's dictionary based on the last fetch and given params.
    The filter is using timestamps with the following logic:
        start date (gt) - if this is the first fetch: use time_range_start param if provided, else use fetch time param.
                          if this is not the fetch: use the last fetch provided
        end date (lt) - use the given time range end param.
        When the `time_method` parameter is set to `Simple-Date` in order to avoid being related to the field datetime format,
            we add the format key to the query dict.
    Args:

        last_fetch (str): last fetch time stamp
        time_range_start (str): start of time range
        time_range_end (str): end of time range
        time_field (str): The field on which the filter the results


    Returns:
        dictionary (Ex. {"range":{'gt': 1000 'lt': 1001}})
    """
    range_dict = {}
    if not last_fetch and time_range_start:  # this is the first fetch
        start_date = dateparser.parse(time_range_start)

        start_time = convert_date_to_timestamp(start_date)
    else:
        start_time = last_fetch

    if start_time:
        range_dict['gt'] = start_time

    if time_range_end:
        end_date = dateparser.parse(time_range_end)
        end_time = convert_date_to_timestamp(end_date)
        range_dict['lt'] = end_time

    if TIME_METHOD == 'Simple-Date':
        range_dict['format'] = ES_DEFAULT_DATETIME_FORMAT

    return {'range': {time_field: range_dict}}


def execute_raw_query(es, raw_query, index=None, size=None, page=None):
    try:
        raw_query = json.loads(raw_query)
        if raw_query.get('query'):
            demisto.debug('query provided already has a query field. Sending as is')
            body = raw_query
        else:
            body = {'query': raw_query}
    except (ValueError, TypeError) as e:
        body = {'query': raw_query}
        demisto.info(f"unable to convert raw query to dictionary, use it as a string\n{e}")

    requested_index = index or FETCH_INDEX

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8]:
        search = Search(using=es, index=requested_index).query(body.get('query'))
        if page and size:
            search = search[page:page + size]
        response = search.execute().to_dict()

    else:  # Elasticsearch v7 and below or OpenSearch
        response = es.search(index=requested_index, body=body, size=size, from_=page)

    return response


def fetch_incidents(proxies):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time') or FETCH_TIME

    es = elasticsearch_builder(proxies)
    time_range_dict = get_time_range(time_range_start=last_fetch)

    if RAW_QUERY:
        response = execute_raw_query(es, RAW_QUERY)
    else:
        query = QueryString(query=FETCH_QUERY + " AND " + TIME_FIELD + ":*")
        # Elastic search can use epoch timestamps (in milliseconds) as date representation regardless of date format.
        search = Search(using=es, index=FETCH_INDEX).filter(time_range_dict)
        search = search.sort({TIME_FIELD: {'order': 'asc'}})[0:FETCH_SIZE].query(query)

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, OPEN_SEARCH]:
            response = search.execute().to_dict()

        else:  # Elasticsearch v7 and below
            # maintain BC by using the ES client directly (avoid using the elasticsearch_dsl library here)
            response = es.search(index=search._index, body=search.to_dict(), **search._params)

    _, total_results = get_total_results(response)

    incidents = []  # type: List

    if total_results > 0:
        if 'Timestamp' in TIME_METHOD:
            incidents, last_fetch = results_to_incidents_timestamp(response, last_fetch)
            demisto.setLastRun({'time': last_fetch})

        else:
            incidents, last_fetch = results_to_incidents_datetime(response, last_fetch or FETCH_TIME)
            demisto.setLastRun({'time': str(last_fetch)})

        demisto.info(f'extracted {len(incidents)} incidents')
    demisto.incidents(incidents)


def parse_subtree(my_map):
    """
    param: my_map - tree element for the schema
    return: tree elements under each branch
    """
    # Recursive search in order to retrieve the elements under the branches in the schema
    res = {}
    for k in my_map:
        if 'properties' in my_map[k]:
            res[k] = parse_subtree(my_map[k]['properties'])
        else:
            res[k] = "type: " + my_map[k].get('type', "")
    return res


def update_elastic_mapping(res_json, elastic_mapping, key):
    """
    A helper function for get_mapping_fields_command, updates the elastic mapping.
    """
    my_map = res_json[key]['mappings']['properties']
    elastic_mapping[key] = {"_id": "doc_id", "_index": key}
    elastic_mapping[key]["_source"] = parse_subtree(my_map)


def get_mapping_fields_command():
    """
    Maps a schema from a given index
    return: Elasticsearch schema structure
    """
    indexes = FETCH_INDEX.split(',')
    elastic_mapping = {}  # type:ignore[var-annotated]
    for index in indexes:
        if index == '':
            res = requests.get(SERVER + '/_mapping', auth=(USERNAME, PASSWORD), verify=INSECURE)
        else:
            res = requests.get(SERVER + '/' + index + '/_mapping', auth=(USERNAME, PASSWORD), verify=INSECURE)
        res_json = res.json()

        # To get mappings for all data streams and indices in a cluster,
        # use _all or * for <target> or omit the <target> parameter - from Elastic API
        if index in ['*', '_all', '']:
            for key in res_json:
                if 'mappings' in res_json[key] and 'properties' in res_json[key]['mappings']:
                    update_elastic_mapping(res_json, elastic_mapping, key)

        elif index.endswith('*'):
            prefix_index = re.compile(index.rstrip('*'))
            for key in res_json:
                if prefix_index.match(key):
                    update_elastic_mapping(res_json, elastic_mapping, key)

        else:
            update_elastic_mapping(res_json, elastic_mapping, index)

    return elastic_mapping


def build_eql_body(query, fields, size, tiebreaker_field, timestamp_field, event_category_field, filter):
    body = {}
    if query is not None:
        body["query"] = query
    if event_category_field is not None:
        body["event_category_field"] = event_category_field
    if fields is not None:
        body["fields"] = fields
    if filter is not None:
        body["filter"] = filter
    if size is not None:
        body["size"] = size
    if tiebreaker_field is not None:
        body["tiebreaker_field"] = tiebreaker_field
    if timestamp_field is not None:
        body["timestamp_field"] = timestamp_field
    return body


def search_eql_command(args, proxies):
    index = args.get('index')
    query = args.get('query')
    fields = args.get('fields')  # fields to display
    size = int(args.get('size', '10'))
    timestamp_field = args.get('timestamp_field')
    event_category_field = args.get('event_category_field')
    sort_tiebreaker = args.get('sort_tiebreaker')
    query_filter = args.get('filter')

    es = elasticsearch_builder(proxies)
    body = build_eql_body(query=query, fields=fields, size=size, tiebreaker_field=sort_tiebreaker,
                          timestamp_field=timestamp_field, event_category_field=event_category_field,
                          filter=query_filter)

    response = es.eql.search(index=index, body=body)

    total_dict, _ = get_total_results(response)
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(index, query, 0,
                                                                               size, total_dict, response, event=True)
    search_human_readable = tableToMarkdown('Search Metadata:', search_context, meta_headers, removeNull=True)
    hits_human_readable = tableToMarkdown('Hits:', hit_tables, hit_headers, removeNull=True)
    total_human_readable = search_human_readable + '\n' + hits_human_readable

    return CommandResults(
        readable_output=total_human_readable,
        outputs_prefix='Elasticsearch.Search',
        outputs=search_context
    )


def index_document(args, proxies):
    """
    Indexes a given document into an Elasticsearch index.
    return: Result returned from elasticsearch lib
    """
    index = args.get('index_name')
    doc = args.get('document')
    doc_id = args.get('id', '')
    es = elasticsearch_builder(proxies)

    if ELASTIC_SEARCH_CLIENT == ELASTICSEARCH_V8:
        if doc_id:
            response = es.index(index=index, id=doc_id, document=doc)  # pylint: disable=E1123,E1120
        else:
            response = es.index(index=index, document=doc)  # pylint: disable=E1123,E1120

    else:  # Elasticsearch version v7 or below, OpenSearch (BC)
        # In elasticsearch lib <8 'document' param is called 'body'
        if doc_id:
            response = es.index(index=index, id=doc_id, body=doc)
        else:
            response = es.index(index=index, body=doc)

    return response


def index_document_command(args, proxies):
    resp = index_document(args, proxies)
    index_context = {
        'id': resp.get('_id', ''),
        'index': resp.get('_index', ''),
        'version': resp.get('_version', ''),
        'result': resp.get('result', '')
    }
    human_readable = {
        'ID': index_context.get('id'),
        'Index name': index_context.get('index'),
        'Version': index_context.get('version'),
        'Result': index_context.get('result')
    }
    headers = [str(k) for k in human_readable]
    readable_output = tableToMarkdown(
        name="Indexed document",
        t=human_readable,
        removeNull=True,
        headers=headers
    )

    if ELASTIC_SEARCH_CLIENT == ELASTICSEARCH_V8:
        resp = resp.body

    result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Elasticsearch.Index',
        outputs=index_context,
        raw_response=resp,
        outputs_key_field='id'
    )
    return result


def get_indices_statistics(client):
    """
    Returns raw statistics and information of all the Elasticsearch indices.
    Args:
        client : The Elasticsearch client

    Returns:
        dict: raw statistics and information of all the Elasticsearch indices.
    """
    stats = client.indices.stats()
    raw_indices_data = stats.get('indices')

    return raw_indices_data


def get_indices_statistics_command(args, proxies):
    """
    Returns statistics and information of the Elasticsearch indices.

    return: A List with Elasticsearch indices info and statistics.
    API reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-stats.html
    """
    limit = arg_to_number(args.get('limit', 50))
    all_results = argToBoolean(args.get('all_results', False))
    indices = []
    es = elasticsearch_builder(proxies)

    # Fetch the statistics for all indices
    raw_indices_data = get_indices_statistics(es)
    for index, index_data in raw_indices_data.items():
        index_stats = {'Name': index,
                       'Status': index_data.get('status', ''),
                       'Health': index_data.get('health', ''),
                       'UUID': index_data.get('uuid', ''),
                       'Documents Count': index_data.get('total', {}).get('docs', {}).get('count', ''),
                       'Documents Deleted': index_data.get('total', {}).get('docs', {}).get('deleted', '')
                       }
        indices.append(index_stats)

    if not all_results:
        indices = indices[:limit]

    readable_output = tableToMarkdown(
        name="Indices Statistics:",
        t=indices,
        removeNull=True,
        headers=[str(k) for k in indices[0]]
    )

    result = CommandResults(
        readable_output=readable_output,
        outputs_prefix='Elasticsearch.IndexStatistics',
        outputs=indices,
        outputs_key_field='UUID',
        raw_response=raw_indices_data
    )
    return result


def main():  # pragma: no cover
    proxies = handle_proxy()
    proxies = proxies if proxies else None
    args = demisto.args()
    try:
        LOG(f'command is {demisto.command()}')
        if demisto.command() == 'test-module':
            test_func(proxies)
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(proxies)
        elif demisto.command() in ['search', 'es-search']:
            search_command(proxies)
        elif demisto.command() == 'get-mapping-fields':
            return_results(get_mapping_fields_command())
        elif demisto.command() == 'es-eql-search':
            return_results(search_eql_command(args, proxies))
        elif demisto.command() == 'es-index':
            return_results(index_document_command(args, proxies))
        elif demisto.command() == 'es-integration-health-check':
            return_results(integration_health_check(proxies))
        elif demisto.command() == 'es-get-indices-statistics':
            return_results(get_indices_statistics_command(args, proxies))

    except Exception as e:
        if 'The client noticed that the server is not a supported distribution of Elasticsearch' in str(e):
            return_error(f'Failed executing {demisto.command()}. Seems that the client does not support the server\'s '
                         f'distribution, Please try using the Open Search client in the instance configuration.'
                         f'\nError message: {str(e)}', error=str(e))
        if 'failed to parse date field' in str(e):
            return_error(f'Failed to execute the {demisto.command()} command. Make sure the `Time field type` is correctly set.',
                         error=str(e))
        return_error(f"Failed executing {demisto.command()}.\nError message: {e}", error=str(e))


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
