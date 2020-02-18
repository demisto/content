import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
from elasticsearch import Elasticsearch, RequestsHttpConnection, NotFoundError
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import QueryString
from datetime import datetime
import requests
import warnings

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
warnings.filterwarnings(action="ignore", message='.*using SSL with verify_certs=False is insecure.')

SERVER = demisto.params().get('url', '').rstrip('/')
CREDS = demisto.params().get('credentials')
if CREDS:
    USERNAME = CREDS.get('identifier')
    PASSWORD = CREDS.get('password')
else:
    USERNAME = None
    PASSWORD = None
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
FETCH_SIZE = 50
INSECURE = not demisto.params().get('insecure', False)
MODULE_TO_FEEDMAP_KEY = 'moduleToFeedMap'


def elasticsearch_builder():
    """Builds an Elasticsearch obj with the necessary credentials, proxy settings and secure connection."""
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

    get_indicators_search_scan()

    demisto.results('ok')


def get_indicators_command():
    search, _ = get_indicators_search_scan()
    limit = int(demisto.args().get('limit', FETCH_SIZE))
    indicators_list: list = []
    ioc_enrch_lst: list = []
    for hit in search.scan():
        hit_lst, hit_enrch_lst = extract_indicators_from_insight_hit(hit)
        indicators_list.extend(hit_lst)
        ioc_enrch_lst.extend(hit_enrch_lst)
        if len(indicators_list) >= limit:
            break
    hr = tableToMarkdown('Indicators', indicators_list, ['name'])
    for ioc_enrch_obj in ioc_enrch_lst:
        hr += tableToMarkdown('Enrichments', ioc_enrch_obj, ['value', 'sourceBrand', 'score'])
    ec = {'ElasticsearchFeed.SharedIndicators': {'Indicators': indicators_list, 'Enrichments': ioc_enrch_lst}}
    return_outputs(hr, ec, indicators_list)


def fetch_indicators_command():
    search, now = get_indicators_search_scan()
    ioc_lst: list = []
    ioc_enrch_lst: list = []
    for hit in search.scan():
        hit_lst, hit_enrch_lst = extract_indicators_from_insight_hit(hit)
        ioc_lst.extend(hit_lst)
        ioc_enrch_lst.extend(hit_enrch_lst)
    if ioc_lst:
        for b in batch(ioc_lst, batch_size=2000):
            demisto.createIndicators(b)
    if ioc_enrch_lst:
        ioc_enrch_batches = create_enrichment_batches(ioc_enrch_lst)
        for enrch_batch in ioc_enrch_batches:
            # ensure batch sizes don't exceed 2000
            for b in batch(enrch_batch, batch_size=2000):
                demisto.createIndicators(b)
    demisto.setLastRun({'time': now})


def get_indicators_search_scan():
    now = datetime.now()
    time_field = "calculatedTime"
    last_fetch = demisto.getLastRun().get('time')
    range_field = {time_field: {'gt': datetime.fromtimestamp(float(last_fetch)), 'lte': now}} if last_fetch else {
        time_field: {'lte': now}}
    es = elasticsearch_builder()
    query = QueryString(query=time_field + ":*")
    tenant_hash = demisto.getIndexHash()
    # all shared indexes minus this tenant shared
    indexes = f'*-shared*,-*{tenant_hash}*-shared*'
    search = Search(using=es, index=indexes).filter({'range': range_field}).query(query)
    return search, str(now.timestamp())


def extract_indicators_from_insight_hit(hit):
    ioc_lst = []
    ioc_enirhcment_list = []
    ioc = results_to_indicator(hit)
    if ioc.get('value'):
        ioc_lst.append(ioc)
        module_to_feedmap = ioc.get(MODULE_TO_FEEDMAP_KEY)
        updated_module_to_feedmap = {}
        if module_to_feedmap:
            ioc_enrichment_obj = []
            for key, val in module_to_feedmap.items():
                if val.get('isEnrichment'):
                    ioc_enrichment_obj.append(val)
                else:
                    updated_module_to_feedmap[key] = val
            ioc_enirhcment_list.append(ioc_enrichment_obj)
            ioc[MODULE_TO_FEEDMAP_KEY] = updated_module_to_feedmap
    return ioc_lst, ioc_enirhcment_list


def results_to_indicator(hit):
    ioc_dict = hit.to_dict()
    ioc_dict['value'] = ioc_dict.get('name')
    ioc_dict['rawJSON'] = dict(ioc_dict)
    return ioc_dict


def create_enrichment_batches(ioc_enrch_lst):
    max_enrch_len = 0
    for ioc_enrch_obj in ioc_enrch_lst:
        max_enrch_len = max(max_enrch_len, len(ioc_enrch_obj))
    enrch_batch_lst = []
    for i in range(max_enrch_len):
        enrch_batch_obj = []
        for ioc_enrch_obj in ioc_enrch_lst:
            if i < len(ioc_enrch_obj):
                enrch_batch_obj.append(ioc_enrch_obj[i])
        enrch_batch_lst.append(enrch_batch_obj)
    return enrch_batch_lst


def main():
    try:
        LOG('command is %s' % (demisto.command(),))
        if demisto.command() == 'test-module':
            test_func()
        elif demisto.command() == 'fetch-indicators':
            fetch_indicators_command()
        elif demisto.command() == 'get-shared-indicators':
            get_indicators_command()
    except Exception as e:
        return_error("Failed executing {}.\nError message: {}".format(demisto.command(), str(e)), error=e)


main()
