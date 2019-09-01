import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
from elasticsearch import Elasticsearch, RequestsHttpConnection
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import QueryString
from datetime import datetime
import json
import requests


SERVER = demisto.params()['url'][:-1] if demisto.params()['url'].endswith('/') else demisto.params()['url']
USERNAME = demisto.params()['username']
PASSWORD = demisto.params()['password']
HTTP_ERRORS = {
    400: '400 Bad Request - Wrong or invalid parameters',
    401: '401 Unauthorized - Wrong or invalid username or password',
    403: '403 Forbidden - The account is not allowed to preform this task',
    404: '404 Not Found - Elasticsearch server was not found',
    410: '410 Gone - Elasticsearch server no longer exists in the service',
    500: '500 Internal Server Error - Internal error',
    503: '503 Service Unavailable'
}


'''VARIABLES FOR FETCH INCIDENTS'''
TIME_FIELD = demisto.params().get('fetch_time_field')
TIME_FORMAT = demisto.params().get('fetch_time_format')
FETCH_INDEX = demisto.params().get('fetch_index')
FETCH_QUERY = demisto.params().get('fetch_query')
FETCH_DAYS = int(str(demisto.params().get('fetch_time'))[0])
INSECURE = not demisto.params().get('insecure')


def get_hit_table(hit, fields):
    table_context = {
        '_index': hit.get('_index'),
        '_id': hit.get('_id'),
        '_type': hit.get('_type'),
        '_score': hit.get('_score'),
    }
    headers = ['_index', '_id', '_type', '_score']
    if hit.get('_source') is not None:
        for source_field in hit.get('_source').keys():
            if fields is None or source_field in fields:  # filtering only the requested fields to display
                table_context[str(source_field)] = hit.get('_source').get(str(source_field))
                headers.append(source_field)

    return table_context, headers


def search_command():
    index = demisto.args()['index']
    query = demisto.args()['query']
    fields = demisto.args().get('fields')  # fields to display
    explain = 'true' == demisto.args().get('explain')
    base_page = int(demisto.args().get('page'))
    size = int(demisto.args().get('size'))
    sort_field = demisto.args().get('sort-field')
    sort_order = demisto.args().get('sort-order')

    if USERNAME is None:
        es = Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection, verify_certs=INSECURE)

    else:
        es = Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection,
                           http_auth=(USERNAME, PASSWORD), verify_certs=INSECURE)

    q = QueryString(query=query)
    s = Search(using=es, index=index).query(q)[base_page:base_page + size]
    if explain:
        s = s.extra(explain=True)

    if fields is not None:
        fields = fields.split(',')
        s = s.source(fields)

    if sort_field is not None:
        s = s.sort({sort_field: {'order': sort_order}})

    response = s.execute()
    response = response.to_dict()
    total_results = response.get('hits').get('total')
    if not str(total_results).isdigit():
        # if in version 7 - total number of hits has value field
        total_results = total_results.get('value')
        total_dict = response.get('hits').get('total')

    else:
        total_dict = {
            'value': total_results,
        }

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

    hit_headers = []  # type: List[String]
    hit_tables = []
    if total_results > 0:
        for hit in response.get('hits').get('hits'):
            single_hit_table, single_header = get_hit_table(hit, fields)
            hit_tables.append(single_hit_table)
            hit_headers = list(set(single_header + hit_headers) - set(['_id', '_type', '_index', '_score']))
        hit_headers = ['_id', '_index', '_type', '_score'] + hit_headers

    search_context['Results'] = response.get('hits').get('hits')
    meta_headers = ['Query', 'took', 'timed_out', 'total', 'max_score', 'Server', 'Page', 'Size']

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': response,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Search Metadata:', search_context, meta_headers) + '\n'
        + tableToMarkdown('Hits:', hit_tables, hit_headers),
        'EntryContext': {
            'Elasticsearch.Search(val.Query == obj.Query && val.Index == obj.Index'
            '&& val.Server == obj.Server && val.Page == obj.Page'
            '&& val.Size == obj.Size)': search_context
        }
    }


def test_func():
    try:
        res = requests.get(SERVER, auth=(USERNAME, PASSWORD), verify=INSECURE)
        if res.status_code >= 400:
            return_error("Failed to connect, Error code: " + HTTP_ERRORS[int(res.status_code)])

    except requests.exceptions.RequestException:
        return_error("Failed to connect, Check Server URL and Port number")

    demisto.results('ok')


def incident_label_maker(source):
    labels = []
    for field in source.keys():
        labels.append({'type': str(field), 'value': str(source.get(field))})

    return labels


def fetch_incidents():
    if TIME_FIELD is None or FETCH_INDEX is None or FETCH_QUERY is None:
        sys.exit(0)  # one or more of the required fields for fetch has no value

    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch = datetime.now() - timedelta(days=FETCH_DAYS)

    else:
        last_fetch = datetime.strptime(
            last_fetch, '%Y-%m-%dT%H:%M:%SZ')

    current_fetch = last_fetch

    if USERNAME is None:
        es = Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection, verify_certs=INSECURE)

    else:
        es = Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection,
                           http_auth=(USERNAME, PASSWORD), verify_certs=INSECURE)

    q = QueryString(query=FETCH_QUERY)
    s = Search(using=es, index=FETCH_INDEX).query(q)
    response = s.execute()
    response = response.to_dict()
    total_results = response.get('hits').get('total')
    if not str(total_results).isdigit():
        # if in version 7 - total number of hits has value field
        total_results = total_results.get('value')
    if total_results > 0:
        incidents = []
        for hit in response.get('hits').get('hits'):
            if hit.get('_source') is not None and hit.get('_source').get(str(TIME_FIELD)) is not None:
                temp_date = datetime.strptime(
                    str(hit.get('_source')[str(TIME_FIELD)]), TIME_FORMAT).isoformat() + 'Z'
                temp_date = datetime.strptime(temp_date, '%Y-%m-%dT%H:%M:%SZ')
                # update last run
                if temp_date > last_fetch:
                    last_fetch = temp_date + timedelta(seconds=1)

                # avoid duplication due to weak time query
                if temp_date > current_fetch:
                    inc = {
                        'type': 'Elasticsearch',
                        'sourceBrand': 'Elasticsearch',
                        'name': 'Elasticsearch: Index: ' + str(FETCH_INDEX) + ", ID: " + str(hit.get('_id')),
                        'details': json.dumps(hit.get('_source')),
                        'rawJSON': json.dumps(hit),
                        'labels': incident_label_maker(hit.get('_source')),
                        'occurred': temp_date.isoformat() + 'Z'
                    }
                    incidents.append(inc)

        demisto.info('extract {} incidents'.format(len(incidents)))
        demisto.setLastRun({'time': last_fetch.isoformat().split('.')[0] + 'Z'})
        demisto.incidents(incidents)


LOG('command is %s' % (demisto.command(),))
handle_proxy()
try:
    if demisto.command() == 'test-module':
        test_func()
        sys.exit(0)
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
        sys.exit(0)
    elif demisto.command() == 'elastic-search' or demisto.command() == 'search':
        demisto.results(search_command())
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
