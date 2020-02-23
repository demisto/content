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

'''VARIABLES FOR FETCH INDICATORS'''
FETCH_SIZE = 50
MODULE_TO_FEEDMAP_KEY = 'moduleToFeedMap'


class ElasticsearchClient:
    def __init__(self, insecure, server, username, password, time_field, time_method, fetch_index):
        self._insecure = insecure
        self._proxy = handle_proxy()
        if not self._proxy:
            self._proxy = None
        self._server = server
        self._http_auth = (username, password) if (username and password) else None

        self.time_field = time_field
        self.time_method = time_method
        self.fetch_index = fetch_index
        self.es = self._elasticsearch_builder()

    def _elasticsearch_builder(self):
        """Builds an Elasticsearch obj with the necessary credentials, proxy settings and secure connection."""
        return Elasticsearch(hosts=[self._server], connection_class=RequestsHttpConnection, http_auth=self._http_auth,
                             verify_certs=self._insecure, proxies=self._proxy)

    def send_test_request(self):
        headers = {
            'Content-Type': "application/json"
        }
        return requests.get(self._server, auth=self._http_auth, verify=self._insecure, headers=headers,
                            proxies=self._proxy)


''' ###################### COMMANDS ###################### '''


def test_command(client, demisto_shared, src_val, src_type, default_type, time_field, time_method, fetch_index):
    """Test instance was set up correctly"""
    if not demisto_shared:
        if not src_val:
            return_error('Please provide a "Source Indicator Value"')
        if not src_type and not default_type:
            return_error('Please provide a "Source Indicator Type" or "Default Indicator Type"')
        if not default_type:
            return_error('Please provide a "Default Indicator Type"')
        if not time_field:
            return_error('Please provide a "Time Field"')
        if not time_method:
            return_error('Please provide a "Time Method"')
        if not fetch_index:
            return_error('Please provide a "Fetch Index"')
    try:
        res = client.send_test_request()
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

    get_scan_insight_format(client)
    demisto.results('ok')


def get_indicators_command(client, demisto_shared, src_val, src_type, default_type):
    """Implements es-get-indicators command"""
    if demisto_shared:
        search, _ = get_scan_insight_format(client)
        get_demisto_indicators(search)
    else:
        search, _ = get_scan_custom_format(client)
        get_custom_indicators(search, src_val, src_type, default_type)


def get_custom_indicators(search, src_val, src_type, default_type):
    """Implements get indicators in custom format"""
    ioc_lst: list = []
    for hit in search.scan():
        hit_lst = extract_indicators_from_custom_hit(hit, src_val, src_type, default_type)
        ioc_lst.extend(hit_lst)
    hr = tableToMarkdown('Indicators', ioc_lst, [src_val])
    ec = {'ElasticsearchFeed.Indicators(val.value === obj.value)': ioc_lst}
    return_outputs(hr, ec, ioc_lst)


def get_demisto_indicators(search):
    """Implements get indicators in insight format"""
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
    ec = {'ElasticsearchFeed.Indicators(val.value === obj.value)': indicators_list,
          'ElasticsearchFeed.Enrichments(val.value === obj.value)': ioc_enrch_lst}
    return_outputs(hr, ec, indicators_list)


def fetch_indicators_command(client, demisto_shared, src_val, src_type, default_type, last_fetch):
    """Implements fetch-indicators command"""
    if demisto_shared:
        now = fetch_and_create_indicators_insight_format(client, last_fetch)
    else:
        now = fetch_and_create_indicators_custom_format(client, src_val, src_type, default_type, last_fetch)
    demisto.setLastRun({'time': now})


def fetch_and_create_indicators_custom_format(client, src_val, src_type, default_type, last_fetch):
    """Fetches hits in custom format and then creates indicators from them"""
    search, now = get_scan_custom_format(client, last_fetch)
    ioc_lst: list = []
    for hit in search.scan():
        hit_lst = extract_indicators_from_custom_hit(hit, src_val, src_type, default_type)
        ioc_lst.extend(hit_lst)
    if ioc_lst:
        for b in batch(ioc_lst, batch_size=2000):
            demisto.createIndicators(b)
    return now


def get_scan_custom_format(client, last_fetch=None):
    """Gets a scan object in custom format"""
    # if method is simple date - convert the date string to datetime
    now = datetime.now()
    es = client.es
    time_method = client.time_method
    last_fetch_timestamp = now.timestamp()
    if last_fetch:
        if 'Simple-Date' == time_method or 'Milliseconds' in time_method:
            last_fetch_timestamp = int(last_fetch) * 1000
        else:
            last_fetch_timestamp = float(last_fetch)
    time_field = client.time_field
    fetch_index = client.fetch_index
    if time_field:
        query = QueryString(query=time_field + ':*')
        range_field = {
            time_field: {'gt': datetime.fromtimestamp(last_fetch_timestamp), 'lte': now}} if last_fetch else {
            time_field: {'lte': now}}
        search = Search(using=es, index=fetch_index).filter({'range': range_field}).query(query)
    else:
        search = Search(using=es, index=fetch_index).query(QueryString(query="*"))
    return search, str(last_fetch_timestamp)


def extract_indicators_from_custom_hit(hit, src_val, src_type, default_type):
    """Extracts indicators in custom format"""
    ioc_lst = []
    ioc = hit_to_indicator(hit, src_val, src_type, default_type)
    if ioc.get('value'):
        ioc_lst.append(ioc)
    return ioc_lst


def fetch_and_create_indicators_insight_format(client, last_fetch):
    """Fetches hits in insight format and then creates indicators from them"""
    search, now = get_scan_insight_format(client, last_fetch)
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
    return now


def get_scan_insight_format(client, last_fetch=None):
    """Gets a scan object in insight format"""
    now = datetime.now()
    time_field = client.time_field
    range_field = {time_field: {'gt': datetime.fromtimestamp(float(last_fetch)), 'lte': now}} if last_fetch else {
        time_field: {'lte': now}}
    es = client.es
    query = QueryString(query=time_field + ":*")
    tenant_hash = demisto.getIndexHash()
    # all shared indexes minus this tenant shared
    indices = client.fetch_index
    if not indices:
        indices = '*-shared*'
        if tenant_hash:
            indices += f',-*{tenant_hash}*-shared*'
    search = Search(using=es, index=indices).filter({'range': range_field}).query(query)
    return search, str(now.timestamp())


def extract_indicators_from_insight_hit(hit):
    """Extracts indicators from an insight hit including enrichments"""
    ioc_lst = []
    ioc_enirhcment_list = []
    ioc = hit_to_indicator(hit)
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


def hit_to_indicator(hit, ioc_val_key='name', ioc_type_key=None, default_ioc_type=None):
    """Convert a single hit to an indicator"""
    ioc_dict = hit.to_dict()
    ioc_dict['value'] = ioc_dict.get(ioc_val_key)
    ioc_dict['rawJSON'] = dict(ioc_dict)
    if ioc_type_key:
        ioc_dict['type'] = ioc_dict.get(ioc_type_key)
    if not ioc_dict.get('type'):
        ioc_dict['type'] = default_ioc_type
    return ioc_dict


def create_enrichment_batches(ioc_enrch_lst):
    """
    Create batches for enrichments, by separating enrichments that come from the same indicator into diff batches
    """
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
        params = demisto.params()
        server = params.get('url', '').rstrip('/')
        creds = params.get('credentials')
        username, password = (creds.get('identifier'), creds.get('password')) if creds else (None, None)
        insecure = not params.get('insecure')
        demisto_shared = params.get('demisto_shared')
        time_field = 'calculatedTime' if demisto_shared else params.get('time_field')
        time_method = params.get('time_method')
        fetch_index = params.get('fetch_index')
        client = ElasticsearchClient(insecure, server, username, password, time_field, time_method, fetch_index)
        src_val = params.get('src_val')
        src_type = params.get('src_type')
        default_type = params.get('default_type')
        last_fetch = demisto.getLastRun().get('time')

        if demisto.command() == 'test-module':
            test_command(client, demisto_shared, src_val, src_type, default_type, time_field, time_method, fetch_index)
        elif demisto.command() == 'fetch-indicators':
            fetch_indicators_command(client, demisto_shared, src_val, src_type, default_type, last_fetch)
        elif demisto.command() == 'es-get-indicators':
            get_indicators_command(client, demisto_shared, src_val, src_type, default_type)
    except Exception as e:
        return_error("Failed executing {}.\nError message: {}".format(demisto.command(), str(e)), error=e)


main()
