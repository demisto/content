import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
import requests
import warnings
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()
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
API_KEY_PREFIX = '_api_key_id:'
MODULE_TO_FEEDMAP_KEY = 'moduleToFeedMap'
FEED_TYPE_GENERIC = 'Generic Feed'
FEED_TYPE_CORTEX = 'Cortex XSOAR Feed'
FEED_TYPE_CORTEX_MT = 'Cortex XSOAR MT Shared Feed'

ELASTIC_SEARCH_CLIENT = demisto.params().get('client_type')
if ELASTIC_SEARCH_CLIENT == 'OpenSearch':
    from opensearchpy import OpenSearch as Elasticsearch, RequestsHttpConnection
    from opensearch_dsl import Search
    from opensearch_dsl.query import QueryString
else:
    from elasticsearch import Elasticsearch, RequestsHttpConnection
    from elasticsearch_dsl import Search
    from elasticsearch_dsl.query import QueryString


class ElasticsearchClient:
    def __init__(self, insecure=None, server=None, username=None, password=None, api_key=None, api_id=None,
                 time_field=None, time_method=None, fetch_index=None, fetch_time=None, query=None, tags=None,
                 tlp_color=None):
        self._insecure = insecure
        self._proxy = handle_proxy()
        # _elasticsearch_builder expects _proxy to be None if empty
        if not self._proxy:
            self._proxy = None
        self._server = server
        self._http_auth = (username, password) if (username and password) else None
        self._api_key = (api_id, api_key) if (api_id and api_key) else None

        self.time_field = time_field
        self.time_method = time_method
        self.fetch_index = fetch_index
        self.fetch_time = fetch_time
        self.query = query
        self.es = self._elasticsearch_builder()
        self.tags = tags
        self.tlp_color = tlp_color

    def _elasticsearch_builder(self):
        """Builds an Elasticsearch obj with the necessary credentials, proxy settings and secure connection."""
        if self._api_key:
            es = Elasticsearch(hosts=[self._server], connection_class=RequestsHttpConnection,
                               verify_certs=self._insecure, proxies=self._proxy, api_key=self._api_key)
        else:
            es = Elasticsearch(hosts=[self._server], connection_class=RequestsHttpConnection, http_auth=self._http_auth,
                               verify_certs=self._insecure, proxies=self._proxy)
        # this should be passed as api_key via Elasticsearch init, but this code ensures it'll be set correctly
        if self._api_key and hasattr(es, 'transport'):
            es.transport.get_connection().session.headers['authorization'] = self._get_api_key_header_val(self._api_key)
        return es

    def send_test_request(self):
        headers = {
            'Content-Type': "application/json"
        }
        if self._api_key:
            headers['authorization'] = self._get_api_key_header_val(self._api_key)
            auth = None
        else:
            auth = self._http_auth
        return requests.get(self._server, verify=self._insecure, headers=headers, proxies=self._proxy, auth=auth)

    @staticmethod
    def _get_api_key_header_val(api_key):
        """
        Check the type of the passed api_key and return the correct header value
        for the `API Key authentication
        <https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html>`
        :arg api_key, either a tuple or a base64 encoded string
        """
        if isinstance(api_key, (tuple, list)):
            s = "{0}:{1}".format(api_key[0], api_key[1]).encode('utf-8')
            return "ApiKey " + base64.b64encode(s).decode('utf-8')
        return "ApiKey " + api_key


def extract_api_from_username_password(username, password):
    """
    Creates (API ID, API Key) tuple from the username/password
    :return: (API ID, API Key)
    """
    return (username[len(API_KEY_PREFIX):], password) if username and username.startswith(
        API_KEY_PREFIX) else (None, None)


''' ###################### COMMANDS ###################### '''


def test_command(client, feed_type, src_val, src_type, default_type, time_method, time_field, fetch_time, query,
                 username, password, api_key, api_id):
    """Test instance was set up correctly"""
    now = datetime.now()
    if username and not password:
        return_error('Please provide a password when using Username + Password authentication')
    elif password and not username:
        return_error('Please provide a username when using Username + Password authentication')
    elif api_id and not api_key:
        return_error('Please provide an API Key when using API ID + API Key authentication')
    elif api_key and not api_id:
        return_error('Please provide an API ID when using API ID + API Key authentication')

    err_msg = ''
    if FEED_TYPE_GENERIC in feed_type:
        if not src_val:
            err_msg += 'Please provide a "Indicator Value Field"\n'
        if not src_type and not default_type:
            err_msg += 'Please provide a "Indicator Type Field" or "Indicator Type"\n'
        elif not default_type:
            err_msg += 'Please provide a "Indicator Type"\n'
        if not time_method:
            err_msg += 'Please provide a "Time Method"\n'
        if time_field and not fetch_time:
            err_msg += 'Please provide a "First Fetch Time"\n'
        if not query:
            err_msg += 'Please provide a "Query"\n'
        if err_msg:
            return_error(err_msg[:-1])
        get_scan_generic_format(client, now)
    else:
        get_scan_insight_format(client, now, feed_type=feed_type)
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

    demisto.results('ok')


def get_indicators_command(client, feed_type, src_val, src_type, default_type):
    """Implements es-get-indicators command"""
    now = datetime.now()
    if FEED_TYPE_GENERIC in feed_type:
        search = get_scan_generic_format(client, now)
        ioc_lst = get_generic_indicators(search, src_val, src_type, default_type, client.tags, client.tlp_color)
        hr = tableToMarkdown('Indicators', ioc_lst, [src_val])
    else:
        # Insight is the name of the indicator object as it's saved into the database
        search = get_scan_insight_format(client, now, feed_type=feed_type)
        ioc_lst, ioc_enrch_lst = get_demisto_indicators(search, client.tags, client.tlp_color)
        hr = tableToMarkdown('Indicators', list(set(map(lambda ioc: ioc.get('name'), ioc_lst))), 'Name')
        if ioc_enrch_lst:
            for ioc_enrch in ioc_enrch_lst:
                hr += tableToMarkdown('Enrichment', ioc_enrch, ['value', 'sourceBrand', 'score'])
    return_outputs(hr, {}, ioc_lst)


def get_generic_indicators(search, src_val, src_type, default_type, tags, tlp_color):
    """Implements get indicators in generic format"""
    ioc_lst: list = []
    for hit in search.scan():
        hit_lst = extract_indicators_from_generic_hit(hit, src_val, src_type, default_type, tags, tlp_color)
        ioc_lst.extend(hit_lst)
    return ioc_lst


def get_demisto_indicators(search, tags, tlp_color):
    """Implements get indicators in insight format"""
    limit = int(demisto.args().get('limit', FETCH_SIZE))
    ioc_lst: list = []
    ioc_enrch_lst: list = []
    for hit in search.scan():
        hit_lst, hit_enrch_lst = extract_indicators_from_insight_hit(hit, tags=tags, tlp_color=tlp_color)
        ioc_lst.extend(hit_lst)
        ioc_enrch_lst.extend(hit_enrch_lst)
        if len(ioc_lst) >= limit:
            break
    return ioc_lst, ioc_enrch_lst


def fetch_indicators_command(client, feed_type, src_val, src_type, default_type, last_fetch):
    """Implements fetch-indicators command"""
    last_fetch_timestamp = get_last_fetch_timestamp(last_fetch, client.time_method, client.fetch_time)
    now = datetime.now()
    ioc_lst: list = []
    ioc_enrch_lst: list = []
    if FEED_TYPE_GENERIC not in feed_type:
        # Insight is the name of the indicator object as it's saved into the database
        search = get_scan_insight_format(client, now, last_fetch_timestamp, feed_type)
        for hit in search.scan():
            hit_lst, hit_enrch_lst = extract_indicators_from_insight_hit(hit, tags=client.tags,
                                                                         tlp_color=client.tlp_color)
            ioc_lst.extend(hit_lst)
            ioc_enrch_lst.extend(hit_enrch_lst)
    else:
        search = get_scan_generic_format(client, now, last_fetch_timestamp)
        for hit in search.scan():
            ioc_lst.extend(extract_indicators_from_generic_hit(hit, src_val, src_type, default_type, client.tags,
                                                               client.tlp_color))

    if ioc_lst:
        for b in batch(ioc_lst, batch_size=2000):
            demisto.createIndicators(b)
    if ioc_enrch_lst:
        ioc_enrch_batches = create_enrichment_batches(ioc_enrch_lst)
        for enrch_batch in ioc_enrch_batches:
            # ensure batch sizes don't exceed 2000
            for b in batch(enrch_batch, batch_size=2000):
                demisto.createIndicators(b)
    demisto.setLastRun({'time': int(now.timestamp() * 1000)})


def get_last_fetch_timestamp(last_fetch, time_method, fetch_time):
    """Get the last fetch timestamp"""
    if last_fetch:
        last_fetch_timestamp = last_fetch
    else:
        last_fetch, _ = parse_date_range(date_range=fetch_time, utc=False)
        # if timestamp: get the last fetch to the correct format of timestamp
        last_fetch_timestamp = int(last_fetch.timestamp() * 1000)
    if 'Timestamp - Seconds' in time_method:
        last_fetch_timestamp = last_fetch_timestamp // 1000
    return last_fetch_timestamp


def get_scan_generic_format(client, now, last_fetch_timestamp=None):
    """Gets a scan object in generic format"""
    # if method is simple date - convert the date string to datetime
    es = client.es
    time_field = client.time_field
    fetch_index = client.fetch_index
    if not fetch_index:
        fetch_index = '_all'
    if time_field:
        query = QueryString(query=time_field + ':*')
        range_field = {
            time_field: {'gt': last_fetch_timestamp, 'lte': now}} if last_fetch_timestamp else {
            time_field: {'lte': now}}
        search = Search(using=es, index=fetch_index).filter({'range': range_field}).query(query)
    else:
        search = Search(using=es, index=fetch_index).query(QueryString(query=client.query))
    return search


def extract_indicators_from_generic_hit(hit, src_val, src_type, default_type, tags, tlp_color):
    """Extracts indicators in generic format"""
    ioc_lst = []
    ioc = hit_to_indicator(hit, src_val, src_type, default_type, tags, tlp_color)
    if ioc.get('value'):
        ioc_lst.append(ioc)
    return ioc_lst


def get_scan_insight_format(client, now, last_fetch_timestamp=None, feed_type=None):
    """Gets a scan object in insight format"""
    time_field = client.time_field
    range_field = {
        time_field: {'gt': last_fetch_timestamp, 'lte': now}} if last_fetch_timestamp else {
        time_field: {'lte': now}}
    es = client.es
    query = QueryString(query=time_field + ":*")
    indices = client.fetch_index
    if feed_type == FEED_TYPE_CORTEX_MT:
        indices = '*-shared*'
        tenant_hash = demisto.getIndexHash()
        if tenant_hash:
            # all shared indexes minus this tenant shared
            indices += f',-*{tenant_hash}*-shared*'
    elif not indices:
        indices = '_all'
    search = Search(using=es, index=indices).filter({'range': range_field}).query(query)
    return search


def extract_indicators_from_insight_hit(hit, tags, tlp_color):
    """Extracts indicators from an insight hit including enrichments"""
    ioc_lst = []
    ioc_enirhcment_list = []
    ioc = hit_to_indicator(hit, tags=tags, tlp_color=tlp_color)
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
            if ioc_enrichment_obj:
                ioc_enirhcment_list.append(ioc_enrichment_obj)
            ioc[MODULE_TO_FEEDMAP_KEY] = updated_module_to_feedmap
    return ioc_lst, ioc_enirhcment_list


def hit_to_indicator(hit, ioc_val_key='name', ioc_type_key=None, default_ioc_type=None, tags=None, tlp_color=None):
    """Convert a single hit to an indicator"""
    ioc_dict = hit.to_dict()
    ioc_dict['value'] = ioc_dict.get(ioc_val_key)
    ioc_dict['rawJSON'] = dict(ioc_dict)
    if default_ioc_type:
        ioc_dict['type'] = default_ioc_type
    elif ioc_type_key:
        ioc_dict['type'] = ioc_dict.get(ioc_type_key)

    ioc_dict['fields'] = {}
    if tags:
        ioc_dict['fields']['tags'] = tags
    if tlp_color:
        ioc_dict['fields']['trafficlightprotocol'] = tlp_color

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
        tags = argToList(params.get('feedTags'))
        tlp_color = params.get('tlp_color')
        feed_type = params.get('feed_type')
        time_field = params.get('time_field') if FEED_TYPE_GENERIC in feed_type else 'calculatedTime'
        time_method = params.get('time_method')
        fetch_index = params.get('fetch_index')
        fetch_time = params.get('fetch_time', '3 days')
        query = params.get('es_query')
        api_id, api_key = extract_api_from_username_password(username, password)
        client = ElasticsearchClient(insecure, server, username, password, api_key, api_id, time_field, time_method,
                                     fetch_index, fetch_time, query, tags, tlp_color)
        src_val = params.get('src_val')
        src_type = params.get('src_type')
        default_type = params.get('default_type')
        last_fetch = demisto.getLastRun().get('time')

        if demisto.command() == 'test-module':
            test_command(client, feed_type, src_val, src_type, default_type, time_method, time_field, fetch_time, query,
                         username, password, api_key, api_id)
        elif demisto.command() == 'fetch-indicators':
            fetch_indicators_command(client, feed_type, src_val, src_type, default_type, last_fetch)
        elif demisto.command() == 'es-get-indicators':
            get_indicators_command(client, feed_type, src_val, src_type, default_type)
    except Exception as e:
        return_error("Failed executing {}.\nError message: {}".format(demisto.command(), str(e)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
