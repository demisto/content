import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
from typing import List
from elasticsearch import Elasticsearch, RequestsHttpConnection, NotFoundError
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import QueryString
from datetime import datetime
import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

SERVER = demisto.params().get('url', '').rstrip('/')
USERNAME = demisto.params().get('credentials', {}).get('identifier')
PASSWORD = demisto.params().get('credentials', {}).get('password')
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
TIME_FIELD = demisto.params().get('fetch_time_field', '')
TIME_FORMAT = demisto.params().get('fetch_time_format', '')
FETCH_INDEX = demisto.params().get('fetch_index', '')
FETCH_QUERY = demisto.params().get('fetch_query', '')
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
FETCH_SIZE = int(demisto.params().get('fetch_size', 50))
INSECURE = not demisto.params().get('insecure', False)


def elasticsearch_builder():
    if USERNAME:
        if PROXY:
            return Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection,
                                 http_auth=(USERNAME, PASSWORD), verify_certs=INSECURE, proxies=handle_proxy())

        else:
            return Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection,
                                 http_auth=(USERNAME, PASSWORD), verify_certs=INSECURE)

    else:
        if PROXY:
            return Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection,
                                 verify_certs=INSECURE, proxies=handle_proxy())

        else:
            return Elasticsearch(hosts=[SERVER], connection_class=RequestsHttpConnection, verify_certs=INSECURE)


def get_hit_table(hit):
    table_context = {
        '_index': hit.get('_index'),
        '_id': hit.get('_id'),
        '_type': hit.get('_type'),
        '_score': hit.get('_score'),
    }
    headers = ['_index', '_id', '_type', '_score']
    if hit.get('_source') is not None:
        for source_field in hit.get('_source').keys():
            table_context[str(source_field)] = hit.get('_source').get(str(source_field))
            headers.append(source_field)

    return table_context, headers


def results_to_context(index, query, base_page, size, total_dict, response):
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
            single_hit_table, single_header = get_hit_table(hit)
            hit_tables.append(single_hit_table)
            hit_headers = list(set(single_header + hit_headers) - {'_id', '_type', '_index', '_score'})
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

    es = elasticsearch_builder()

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
    str_error = []  # type:List
    if TIME_FIELD == '' or TIME_FIELD is None:
        str_error.append("Index time field is not configured.")

    if FETCH_INDEX == '' or FETCH_INDEX is None:
        str_error.append("Index is not configured.")

    if FETCH_QUERY == '' or FETCH_QUERY is None:
        str_error.append("Query by which to fetch incidents is not configured.")

    if TIME_FORMAT == '' or TIME_FORMAT is None:
        str_error.append("Time format is not configured.")

    if len(str_error) > 0:
        return_error("Got the following errors in test:\nFetches incidents is enabled.\n" + '\n'.join(str_error))


def test_general_query(es):
    try:
        query = QueryString(query='*')
        search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]
        response = search.execute().to_dict()
        _, total_results = get_total_results(response)

    except NotFoundError as e:
        return_error("Fetch incidents test failed.\nError message: {}.".format(str(e).split(',')[2][2:-1]))


def test_time_field_query(es):
    query = QueryString(query=TIME_FIELD + ':*')
    search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]
    response = search.execute().to_dict()
    _, total_results = get_total_results(response)

    if total_results == 0:
        # failed in getting the TIME_FIELD
        return_error("Fetch incidents test failed.\nDate field value incorrect [{}].".format(TIME_FIELD))

    else:
        return response


def test_fetch_query(es):
    query = QueryString(query=str(TIME_FIELD) + ":* AND " + FETCH_QUERY)
    search = Search(using=es, index=FETCH_INDEX).query(query)[0:1]
    response = search.execute().to_dict()
    _, total_results = get_total_results(response)

    if total_results > 0:
        return response

    else:
        # failed to get the TIME_FIELD with the FETCH_QUERY
        # this can happen and not be an error if the FETCH_QUERY doesn't have results yet.
        # Thus this does not return an error message
        return None


def test_func():
    headers = {
        'Content-Type': "application/json"
    }

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
                                 "The following error occurred: {}".format(HTTP_ERRORS.get(res.status_code)))

                else:
                    # if it is unknown error - get the message from the error itself
                    return_error("Failed to connect. The following error occurred: {}".format(str(e)))

    except requests.exceptions.RequestException as e:
        return_error("Failed to connect. Check Server URL field and port number.\nError message: " + str(e))

    if demisto.params().get('isFetch'):
        # check the existence of all necessary fields for fetch
        fetch_params_check()

        try:
            # build general Elasticsearch class
            es = elasticsearch_builder()

            # test if FETCH_INDEX exists
            test_general_query(es)

            # test if TIME_FIELD in index exists
            response = test_time_field_query(es)

            # try to get response from FETCH_QUERY - if exists check the time field from that query
            temp = test_fetch_query(es)
            if temp:
                response = temp

            hit_date = str(response.get('hits', {}).get('hits')[0].get('_source').get(str(TIME_FIELD)))
            datetime.strptime(hit_date, TIME_FORMAT)

        except ValueError as e:
            return_error("Inserted time format is incorrect.\n" + str(e) + '\n' + TIME_FIELD + ' fetched: ' + hit_date)

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
            hit_date = datetime.strptime(str(hit.get('_source')[str(TIME_FIELD)]), TIME_FORMAT)
            # update last run
            if hit_date > last_fetch:
                last_fetch = hit_date

            # avoid duplication due to weak time query
            if hit_date > current_fetch:
                inc = {
                    'name': 'Elasticsearch: Index: ' + str(hit.get('_index')) + ", ID: " + str(hit.get('_id')),
                    'rawJSON': json.dumps(hit),
                    'labels': incident_label_maker(hit.get('_source')),
                    'occurred': hit_date.isoformat() + 'Z'
                }
                incidents.append(inc)

    return incidents, last_fetch


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch, _ = parse_date_range(date_range=FETCH_TIME, date_format=TIME_FORMAT, utc=False, to_timestamp=False)
        last_fetch = datetime.strptime(str(last_fetch), TIME_FORMAT)

    else:
        last_fetch = datetime.strptime(last_fetch, TIME_FORMAT)

    current_fetch = last_fetch

    es = elasticsearch_builder()

    query = QueryString(query=FETCH_QUERY + " AND " + TIME_FIELD + ":*")
    search = Search(using=es, index=FETCH_INDEX).filter({'range': {TIME_FIELD: {'gt': last_fetch}}})
    search = search.sort({TIME_FIELD: {'order': 'asc'}})[0:FETCH_SIZE].query(query)
    response = search.execute().to_dict()
    _, total_results = get_total_results(response)

    incidents = []  # type: List
    if total_results > 0:
        incidents, last_fetch = results_to_incidents(response, current_fetch, last_fetch)

        demisto.info('extract {} incidents'.format(len(incidents)))
        demisto.setLastRun({'time': datetime.strftime(last_fetch, TIME_FORMAT)})

    demisto.incidents(incidents)


try:
    LOG('command is %s' % (demisto.command(),))
    if demisto.command() == 'test-module':
        test_func()
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()
    elif demisto.command() in ['search', 'es-search']:
        search_command()
except Exception as e:
    return_error("Failed executing {}.\nError message: {}".format(demisto.command(), str(e)), error=e)
