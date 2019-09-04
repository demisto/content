import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
from typing import List
from elasticsearch import Elasticsearch, RequestsHttpConnection
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import QueryString
from datetime import datetime
import json
import requests


SERVER = demisto.params()['url'].rstrip('/')
USERNAME = demisto.params().get('credentials', {}).get('identifier')
PASSWORD = demisto.params().get('credentials', {}).get('password')
HTTP_ERRORS = {
    400: '400 Bad Request - Wrong or invalid parameters',
    401: '401 Unauthorized - Wrong or invalid username or password',
    403: '403 Forbidden - The account is not allowed to preform this task',
    404: '404 Not Found - Elasticsearch server was not found',
    408: '408 Timeout - Check port number or Elasticsearch server credentials',
    410: '410 Gone - Elasticsearch server no longer exists in the service',
    500: '500 Internal Server Error - Internal error',
    503: '503 Service Unavailable'
}


'''VARIABLES FOR FETCH INCIDENTS'''
TIME_FIELD = demisto.params().get('fetch_time_field', '')
TIME_FORMAT = demisto.params().get('fetch_time_format', '')
FETCH_INDEX = demisto.params().get('fetch_index', '')
FETCH_QUERY = demisto.params().get('fetch_query', '')
FETCH_DAYS = int(demisto.params().get('fetch_time', 3))
INSECURE = not demisto.params().get('insecure', False)


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


def results_to_context(index, query, base_page, size, total_dict, fields, response):
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

    hit_headers = []  # type: List
    hit_tables = []
    if total_dict.get('value') > 0:
        for hit in response.get('hits').get('hits'):
            single_hit_table, single_header = get_hit_table(hit, fields)
            hit_tables.append(single_hit_table)
            hit_headers = list(set(single_header + hit_headers) - set(['_id', '_type', '_index', '_score']))
        hit_headers = ['_id', '_index', '_type', '_score'] + hit_headers

    search_context['Results'] = response.get('hits').get('hits')
    meta_headers = ['Query', 'took', 'timed_out', 'total', 'max_score', 'Server', 'Page', 'Size']
    return search_context, meta_headers, hit_tables, hit_headers


def get_total_results(response_dict):
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


def search_command():
    index = demisto.args().get('index')
    query = demisto.args().get('query')
    fields = demisto.args().get('fields')  # fields to display
    explain = 'true' == demisto.args().get('explain')
    base_page = int(demisto.args().get('page'))
    size = int(demisto.args().get('size'))
    sort_field = demisto.args().get('sort-field')
    sort_order = demisto.args().get('sort-order')

    es = Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection,
                       http_auth=(USERNAME, PASSWORD), verify_certs=INSECURE)

    que = QueryString(query=query)
    search = Search(using=es, index=index).query(que)[base_page:base_page + size]
    if explain:
        # if 'explain parameter is set to 'true' - adds explanation section to search results
        search = search.extra(explain=True)

    if fields is not None:
        fields = fields.split(',')
        search = search.source(fields)

    if sort_field is not None:
        search = search.sort({sort_field: {'order': sort_order}})

    response = search.execute().to_dict()
    total_dict, total_results = get_total_results(response)
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(index, query, base_page,
                                                                               size, total_dict, fields, response)
    return_outputs(tableToMarkdown('Search Metadata:', search_context, meta_headers, removeNull=True) + '\n'
                   + tableToMarkdown('Hits:', hit_tables, hit_headers, removeNull=True),
                   {
                        'Elasticsearch.Search(val.Query == obj.Query && val.Index == obj.Index'
                        '&& val.Server == obj.Server && val.Page == obj.Page'
                        '&& val.Size == obj.Size)': search_context
                   },
                   response)


def test_func():
    try:
        res = requests.get(SERVER, auth=(USERNAME, PASSWORD), verify=INSECURE)
        if res.status_code >= 400:
            return_error("Failed to connect, Got the following error: " + HTTP_ERRORS[int(res.status_code)])

    except requests.exceptions.RequestException:
        return_error("Failed to connect, Check Server URL and Port number")

    if demisto.params().get('isFetch'):
        str_error = ''
        if TIME_FIELD is None:
            str_error = str_error + "\nNo time field for fetch"

        if FETCH_INDEX is None:
            str_error = str_error + "\nNo index for fetch"

        if FETCH_QUERY is None:
            str_error = str_error + "\nNo query for fetch"

        if TIME_FORMAT is None:
            str_error = str_error + "\nNo time format for fetch"

        if str_error != '':
            return_error("Got The following errors in test: " + str_error)

        try:
            es = Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection,
                               http_auth=(USERNAME, PASSWORD), verify_certs=INSECURE)

            query = QueryString(query=str(TIME_FIELD) + ":*")
            search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]
            response = search.execute().to_dict()
            _, total_results = get_total_results(response)
            if total_results > 0:
                hit_date = str(response.get('hits', {}).get('hits')[0].get('_source').get(str(TIME_FIELD)))
                datetime.strptime(hit_date, TIME_FORMAT).isoformat() + 'Z'

        except ValueError as e:
            return_error("Inserted time format does not match. " + str(e))

    demisto.results('ok')


def incident_label_maker(source):
    labels = []
    for field in source.keys():
        labels.append({'type': str(field), 'value': str(source.get(field))})

    return labels


def results_to_incidents(response, current_fetch, last_fetch):
    incidents = []
    for hit in response.get('hits', {}).get('hits'):
        if hit.get('_source') is not None and hit.get('_source').get(str(TIME_FIELD)) is not None:
            hit_date = datetime.strptime(
                str(hit.get('_source')[str(TIME_FIELD)]), TIME_FORMAT).isoformat() + 'Z'
            hit_date = datetime.strptime(hit_date, '%Y-%m-%dT%H:%M:%SZ')
            # update last run
            if hit_date > last_fetch:
                last_fetch = hit_date

            # avoid duplication due to weak time query
            if hit_date > current_fetch:
                inc = {
                    'type': 'Elasticsearch',
                    'sourceBrand': 'Elasticsearch',
                    'name': 'Elasticsearch: Index: ' + str(FETCH_INDEX) + ", ID: " + str(hit.get('_id')),
                    'details': json.dumps(hit.get('_source')),
                    'rawJSON': json.dumps(hit),
                    'labels': incident_label_maker(hit.get('_source')),
                    'occurred': hit_date.isoformat() + 'Z'
                }
                incidents.append(inc)

    return incidents


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch = datetime.now() - timedelta(days=FETCH_DAYS)

    else:
        last_fetch = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ')

    current_fetch = last_fetch

    es = Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection,
                       http_auth=(USERNAME, PASSWORD), verify_certs=INSECURE)

    query = QueryString(query=FETCH_QUERY)
    search = Search(using=es, index=FETCH_INDEX).query(query)
    response = search.execute().to_dict()
    _, total_results = get_total_results(response)

    if total_results > 0:
        incidents = results_to_incidents(response, current_fetch, last_fetch)

        demisto.info('extract {} incidents'.format(len(incidents)))
        demisto.setLastRun({'time': last_fetch.isoformat().split('.')[0] + 'Z'})
        demisto.incidents(incidents)


try:
    LOG('command is %s' % (demisto.command(),))
    handle_proxy()
    if demisto.command() == 'test-module':
        test_func()
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
    elif demisto.command() == 'search':
        search_command()
except Exception as e:
    return_error(str(e))
    LOG.print_log()
