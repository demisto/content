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
FETCH_LIMIT = 10000
API_KEY_PREFIX = '_api_key_id:'
MODULE_TO_FEEDMAP_KEY = 'moduleToFeedMap'
FEED_TYPE_GENERIC = 'Generic Feed'
FEED_TYPE_CORTEX = 'Cortex XSOAR Feed'
FEED_TYPE_CORTEX_MT = 'Cortex XSOAR MT Shared Feed'
TIME_FORMAT = 'strict_date_optional_time||date_optional_time||epoch_millis||epoch_second'
# The time format is added to the fetch query to support all possible time formats the integration allows

ELASTICSEARCH_V8 = 'Elasticsearch_v8'
OPEN_SEARCH = 'OpenSearch'
ELASTIC_SEARCH_CLIENT = demisto.params().get('client_type')
if ELASTIC_SEARCH_CLIENT == OPEN_SEARCH:
    from opensearchpy import OpenSearch as Elasticsearch, RequestsHttpConnection
    from opensearch_dsl import Search
    from opensearch_dsl.query import QueryString
elif ELASTIC_SEARCH_CLIENT == ELASTICSEARCH_V8:
    from elasticsearch import Elasticsearch  # type: ignore[assignment]
    from elasticsearch.helpers import scan  # type: ignore[assignment]
    from elasticsearch_dsl import Search
    from elasticsearch_dsl.query import QueryString
else:  # Elasticsearch (<= v7)
    from elasticsearch7 import Elasticsearch, RequestsHttpConnection  # type: ignore[assignment]
    from elasticsearch7.helpers import scan  # type: ignore[assignment]
    from elasticsearch_dsl import Search
    from elasticsearch_dsl.query import QueryString


class ElasticsearchClient:
    def __init__(self, insecure=None, server=None, username=None, password=None, api_key=None, api_id=None,
                 time_field=None, time_method=None, fetch_index=None, fetch_time=None, query=None, tags=None,
                 tlp_color=None, enrichment_excluded: bool = False):
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
        self.enrichment_excluded = enrichment_excluded

    def _elasticsearch_builder(self):
        """Builds an Elasticsearch obj with the necessary credentials, proxy settings and secure connection."""
        if ELASTIC_SEARCH_CLIENT == ELASTICSEARCH_V8:
            # The input of proxy configuration is currently missing on client v8 - in this case we are dependent on the client
            # using the proxy environment variables.
            # To add the proxy parameter to the Elasticsearch client v8 - uncomment the following section and add
            # node_class=CustomHttpNode(proxy=proxy) to the Elasticsearch() constructor:
            # Reference- https://github.com/elastic/elastic-transport-python/issues/53#issuecomment-1447903214
            # proxy = self._proxy
            # class CustomHttpNode(RequestsHttpNode):
            #     def __init__(self, proxy, *args, **kwargs):
            #         super().__init__(*args, **kwargs)
            #         self.session.proxies = proxy
            if self._api_key:
                es = Elasticsearch(hosts=[self._server], verify_certs=self._insecure, api_key=self._api_key)
            else:
                es = Elasticsearch(hosts=[self._server], basic_auth=self._http_auth, verify_certs=self._insecure)

        else:  # Elasticsearch v7 and below or OpenSearch
            if self._api_key:
                es = Elasticsearch(hosts=[self._server], connection_class=RequestsHttpConnection,  # pylint: disable=E0606
                                   verify_certs=self._insecure, proxies=self._proxy, api_key=self._api_key)
            else:
                es = Elasticsearch(hosts=[self._server], connection_class=RequestsHttpConnection, http_auth=self._http_auth,
                                   verify_certs=self._insecure, proxies=self._proxy)

        # this should be passed as api_key via Elasticsearch init, but this code ensures it'll be set correctly
        if self._api_key and hasattr(es, 'transport'):
            es.transport.get_connection().session.headers["authorization"] = self._get_api_key_header_val(  # type: ignore
                self._api_key
            )
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
        if isinstance(api_key, tuple | list):
            s = f"{api_key[0]}:{api_key[1]}".encode()
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
        get_scan_generic_format(client)
    else:
        get_scan_insight_format(client, feed_type=feed_type)
    try:
        res = client.send_test_request()

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
                    return_error(f"Failed to connect. The following error occurred: {str(e)}")

        elif res.status_code == 200:
            verify_es_server_version(res.json())

    except requests.exceptions.RequestException as e:
        return_error("Failed to connect. Check Server URL field and port number.\nError message: " + str(e))

    demisto.results('ok')


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
            elif int(major_version) <= 7 and ELASTIC_SEARCH_CLIENT not in [OPEN_SEARCH, 'ElasticSearch']:
                raise ValueError(f'Configuration Error: Your Elasticsearch server is version {es_server_version}. '
                                 f'Please ensure that the client type is set to ElasticSearch or {OPEN_SEARCH}. '
                                 f'For more information please see the integration documentation.')


def get_indicators_command(client, feed_type, src_val, src_type, default_type):
    """Implements es-get-indicators command"""
    if FEED_TYPE_GENERIC in feed_type:  # Generic Feed
        search = get_scan_generic_format(client)
        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, OPEN_SEARCH]:
            ioc_lst = get_generic_indicators(search, src_val, src_type, default_type, client.tags, client.tlp_color,
                                             client.enrichment_excluded)
        else:  # Elasticsearch v7 and below
            ioc_lst = get_generic_indicators_elastic_v7(client.es, search, src_val, src_type, default_type, client.tags,
                                                        client.tlp_color, client.enrichment_excluded)

        hr = tableToMarkdown('Indicators', ioc_lst, [src_val])

    else:  # Demisto Feed types
        # Insight is the name of the indicator object as it's saved into the database
        search = get_scan_insight_format(client, feed_type=feed_type)

        if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, OPEN_SEARCH]:
            ioc_lst, ioc_enrch_lst = get_demisto_indicators(search, client.tags, client.tlp_color, client.enrichment_excluded)
        else:  # Elasticsearch v7 and below
            ioc_lst, ioc_enrch_lst = get_demisto_indicators_elastic_v7(
                client.es, search, client.tags, client.tlp_color, client.enrichment_excluded)
        hr = tableToMarkdown('Indicators', list({ioc.get('name') for ioc in ioc_lst}), 'Name')

        if ioc_enrch_lst:
            for ioc_enrch in ioc_enrch_lst:
                hr += tableToMarkdown('Enrichment', ioc_enrch, ['value', 'sourceBrand', 'score'])
    return_outputs(hr, {}, ioc_lst)


def get_generic_indicators_elastic_v7(es, search, src_val, src_type, default_type, tags, tlp_color, enrichment_excluded):
    """Implements get indicators in generic format for Elasticsearch v7 and below.
    We maintain BC for versions <= 7 by using the ES client directly (from the elasticsearch7 library) instead of using the
    elasticsearch_dsl library which is compatible for elasticsearch client versions >=8.
    """
    limit = int(demisto.args().get('limit', FETCH_SIZE))
    ioc_lst: list = []
    scan_res = scan(es, query=search.to_dict(), index=search._index, **search._params)  # pylint: disable=E0606
    for hit in scan_res:
        hit_lst = extract_indicators_from_generic_hit(hit, src_val, src_type, default_type, tags, tlp_color, enrichment_excluded)
        ioc_lst.extend(hit_lst)
        if len(ioc_lst) >= limit:
            break
    return ioc_lst


def get_generic_indicators(search, src_val, src_type, default_type, tags, tlp_color, enrichment_excluded):
    """Implements get indicators in generic format"""
    limit = int(demisto.args().get('limit', FETCH_SIZE))
    ioc_lst: list = []
    for hit in search.scan():
        hit_lst = extract_indicators_from_generic_hit(hit, src_val, src_type, default_type, tags, tlp_color, enrichment_excluded)
        ioc_lst.extend(hit_lst)
        if len(ioc_lst) >= limit:
            break
    return ioc_lst


def get_demisto_indicators_elastic_v7(es, search, tags, tlp_color, enrichment_excluded):
    """Implements get indicators in insight format for Elasticsearch v7 and below.
    We maintain BC for versions <= 7 by using the ES client directly (from the elasticsearch7 library) instead of using the
    elasticsearch_dsl library which is compatible for elasticsearch client versions >=8.
    """
    limit = int(demisto.args().get('limit', FETCH_SIZE))
    ioc_lst: list = []
    ioc_enrch_lst: list = []
    scan_res = scan(es, query=search.to_dict(), index=search._index, **search._params)
    for hit in scan_res:
        hit_lst, hit_enrch_lst = extract_indicators_from_insight_hit(hit, tags=tags, tlp_color=tlp_color,
                                                                     enrichment_excluded=enrichment_excluded)
        ioc_lst.extend(hit_lst)
        ioc_enrch_lst.extend(hit_enrch_lst)
        if len(ioc_lst) >= limit:
            break
    return ioc_lst, ioc_enrch_lst


def get_demisto_indicators(search, tags, tlp_color, enrichment_excluded):
    """Implements get indicators in insight format"""
    limit = int(demisto.args().get('limit', FETCH_SIZE))
    ioc_lst: list = []
    ioc_enrch_lst: list = []
    for hit in search.scan():
        hit_lst, hit_enrch_lst = extract_indicators_from_insight_hit(hit, tags=tags, tlp_color=tlp_color,
                                                                     enrichment_excluded=enrichment_excluded)
        ioc_lst.extend(hit_lst)
        ioc_enrch_lst.extend(hit_enrch_lst)
        if len(ioc_lst) >= limit:
            break
    return ioc_lst, ioc_enrch_lst


def update_last_fetch(client, ioc_lst):
    demisto.debug(f"ElasticSearchFeed: Length of the indicators to fetch is: {len(ioc_lst)}")
    last_calculated_timestamp = None
    last_ids = []
    for ioc in reversed(ioc_lst):
        calculate_time: Optional[datetime] = ''  # type: ignore
        if time_val := ioc.get(client.time_field):
            calculate_time = dateparser.parse(time_val)
        if not calculate_time:
            demisto.info(f"ioc {ioc.get('value')} is missing time_field: {client.time_field}")
            break
        calculate_timestamp = int(calculate_time.timestamp() * 1000)
        if not last_calculated_timestamp or calculate_timestamp >= last_calculated_timestamp:
            last_calculated_timestamp = calculate_timestamp
            last_ids.append(ioc.get('id'))
        else:
            demisto.debug(f"FeedElasticSearch: {last_calculated_timestamp=}")
            demisto.debug(f"FeedElasticSearch: {calculate_timestamp=}")
            break
    if last_calculated_timestamp is None:
        # possible cases:
        # 1. We didn't fetch any indicators in this cycle
        # 2. This is a fetch of indicators from a generic feed type without a client.time_field
        last_calculated_timestamp = int(datetime.now().timestamp() * 1000)
    demisto.info(f"FeedElasticSearch: The length of the indicators of the last time: {len(last_ids)}")
    demisto.debug(f"FeedElasticSearch: The last ids which were fetched with the same last time: {last_ids}")
    return last_calculated_timestamp, last_ids


def fetch_indicators_elastic_v7(client, last_fetch_timestamp, feed_type, fetch_limit, src_val, src_type, default_type):
    """fetching indicators from the elasticsearch server.
    This function is used for client versions Elasticsearch (v7 and below) only.
    """
    indicators_list = []
    indicators_enrch_list = []

    demisto.debug("Fetching indicators from an Elasticsearch server version <= 7")

    if FEED_TYPE_GENERIC not in feed_type:  # Demisto Feed types
        # Insight is the name of the indicator object as it's saved into the database
        search = get_scan_insight_format(client, last_fetch_timestamp, feed_type, fetch_limit)
        search_res = client.es.search(index=search._index, body=search.to_dict(), **search._params)
        if search_res:
            res = search_res.get("hits", []).get("hits", [])
            for hit in res:
                hit_list, hit_enrch_list = extract_indicators_from_insight_hit(hit, tags=client.tags,
                                                                               tlp_color=client.tlp_color,
                                                                               enrichment_excluded=client.enrichment_excluded)
                indicators_list.extend(hit_list)
                indicators_enrch_list.extend(hit_enrch_list)

    else:  # Generic Feed type
        search = get_scan_generic_format(client, last_fetch_timestamp, fetch_limit)

        if client.time_field:  # if time field exist, we will fetch by using this field in the search
            search_res = client.es.search(index=search._index, body=search.to_dict(), **search._params)
            if search_res:
                res = search_res.get("hits", []).get("hits", [])
                for hit in res:
                    indicators_list.extend(extract_indicators_from_generic_hit(hit, src_val, src_type, default_type, client.tags,
                                                                               client.tlp_color, client.enrichment_excluded))
        else:  # if time field isn't set we have to scan for all indicators (in every cycle)
            scan_res = scan(client.es, query=search.to_dict(), index=search._index, **search._params)
            for hit in scan_res:
                indicators_list.extend(extract_indicators_from_generic_hit(hit, src_val, src_type, default_type, client.tags,
                                                                           client.tlp_color, client.enrichment_excluded))

    return indicators_list, indicators_enrch_list


def fetch_indicators(client, last_fetch_timestamp, feed_type, fetch_limit, src_val, src_type, default_type):
    """fetching indicators from the elasticsearch server.
    This function is used for client versions Elasticsearch_v8 and OpenSearch only.
    """
    indicators_list = []
    indicators_enrch_list = []

    if FEED_TYPE_GENERIC not in feed_type:  # Demisto Feed types
        # Insight is the name of the indicator object as it's saved into the database
        search = get_scan_insight_format(client, last_fetch_timestamp, feed_type, fetch_limit)
        for hit in search:
            hit_list, hit_enrch_list = extract_indicators_from_insight_hit(hit, tags=client.tags,
                                                                           tlp_color=client.tlp_color,
                                                                           enrichment_excluded=client.enrichment_excluded)
            indicators_list.extend(hit_list)
            indicators_enrch_list.extend(hit_enrch_list)

    else:  # Generic Feed type
        search = get_scan_generic_format(client, last_fetch_timestamp, fetch_limit)
        for hit in search if client.time_field else search.scan():  # if time field isn't set we have to scan all (in every cycle)
            indicators_list.extend(extract_indicators_from_generic_hit(hit, src_val, src_type, default_type, client.tags,
                                                                       client.tlp_color, client.enrichment_excluded))

    return indicators_list, indicators_enrch_list


def fetch_indicators_command(client, feed_type, src_val, src_type, default_type, last_fetch, fetch_limit):
    """Implements fetch-indicators command"""
    last_fetch_timestamp = get_last_fetch_timestamp(last_fetch, client.time_method, client.fetch_time)
    demisto.debug(f"FeedElasticSearch: last_fetch_timestamp is: {last_fetch_timestamp}")
    prev_iocs_ids = demisto.getLastRun().get("ids", [])
    ioc_lst: list = []
    ioc_enrch_lst: list = []

    demisto.debug(f"Starting fetch indicators - Elasticsearch client type is: {ELASTIC_SEARCH_CLIENT}")

    if ELASTIC_SEARCH_CLIENT in [ELASTICSEARCH_V8, OPEN_SEARCH]:
        ioc_lst, ioc_enrch_lst = fetch_indicators(client, last_fetch_timestamp, feed_type, fetch_limit, src_val,
                                                  src_type, default_type)
    else:  # Elasticsearch v7 and below (backwards compatibility)
        ioc_lst, ioc_enrch_lst = fetch_indicators_elastic_v7(client, last_fetch_timestamp, feed_type, fetch_limit, src_val,
                                                             src_type, default_type)

    ioc_lst = list(filter(lambda ioc: ioc.get("id") not in prev_iocs_ids, ioc_lst))

    if ioc_lst:
        for b in batch(ioc_lst, batch_size=2000):
            demisto.createIndicators(b)
    last_calculated_timestamp, last_ids = update_last_fetch(client, ioc_lst)
    if str(last_calculated_timestamp) == last_fetch:
        last_ids.extend(prev_iocs_ids)
    if ioc_enrch_lst:
        ioc_enrch_batches = create_enrichment_batches(ioc_enrch_lst)
        for enrch_batch in ioc_enrch_batches:
            # ensure batch sizes don't exceed 2000
            for b in batch(enrch_batch, batch_size=2000):
                demisto.createIndicators(b)
    demisto.setLastRun({'time': str(last_calculated_timestamp), 'ids': last_ids})


def get_last_fetch_timestamp(last_fetch, time_method, fetch_time):
    """Get the last fetch timestamp"""
    if last_fetch:
        last_fetch_timestamp = last_fetch
    else:
        last_fetch = dateparser.parse(fetch_time)
        if not last_fetch:
            raise ValueError("Failed to parse the fetch time")
        # if timestamp: get the last fetch to the correct format of timestamp
        last_fetch_timestamp = int(last_fetch.timestamp() * 1000)
    if 'Timestamp - Seconds' in time_method:
        last_fetch_timestamp = last_fetch_timestamp // 1000
    return last_fetch_timestamp


def get_scan_generic_format(client, last_fetch_timestamp=None, fetch_limit=FETCH_LIMIT):
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
            time_field: {'gte': str(last_fetch_timestamp), 'lte': "now", 'format': TIME_FORMAT}} if last_fetch_timestamp else {
            time_field: {'lte': "now", 'format': TIME_FORMAT}}
        search = Search(using=es, index=fetch_index).filter({'range': range_field}).extra(
            size=fetch_limit).sort({time_field: {'order': 'asc'}}).query(query)
    else:
        search = Search(using=es, index=fetch_index).query(QueryString(query=client.query))
    return search


def extract_indicators_from_generic_hit(hit, src_val, src_type, default_type, tags, tlp_color, enrichment_excluded: bool = False):
    """Extracts indicators in generic format"""
    ioc_lst = []
    ioc = hit_to_indicator(hit, src_val, src_type, default_type, tags, tlp_color, enrichment_excluded)
    if ioc.get('value'):
        ioc_lst.append(ioc)
    return ioc_lst


def get_scan_insight_format(client, last_fetch_timestamp=None, feed_type=None, fetch_limit=FETCH_LIMIT):
    """Gets a scan object in insight format"""
    time_field = client.time_field
    range_field = {
        time_field: {'gte': str(last_fetch_timestamp), 'lte': "now", 'format': TIME_FORMAT}} if last_fetch_timestamp else {
        time_field: {'lte': "now", 'format': TIME_FORMAT}}
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
    search = Search(using=es, index=indices).filter({'range': range_field}).extra(
        size=fetch_limit).sort({time_field: {'order': 'asc'}}).query(query)

    return search


def extract_indicators_from_insight_hit(hit, tags, tlp_color, enrichment_excluded: bool = False):
    """Extracts indicators from an insight hit including enrichments"""
    ioc_lst = []
    ioc_enirhcment_list = []
    ioc = hit_to_indicator(hit, tags=tags, tlp_color=tlp_color, enrichment_excluded=enrichment_excluded)
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


def hit_to_indicator(hit, ioc_val_key='name', ioc_type_key=None, default_ioc_type=None, tags=None, tlp_color=None,
                     enrichment_excluded: bool = False):
    """Convert a single hit to an indicator"""
    ioc_dict: dict = hit
    if ELASTIC_SEARCH_CLIENT not in [ELASTICSEARCH_V8, OPEN_SEARCH] and isinstance(hit, dict):
        # For client version elastic <= v7, we get a different hit structure during the fetch indicators (due to BC code changes).
        ioc_dict = hit.get("_source", {})
    else:
        ioc_dict = hit.to_dict()
    ioc_dict['value'] = ioc_dict.get(ioc_val_key)
    ioc_dict['rawJSON'] = dict(ioc_dict)
    if default_ioc_type:
        ioc_dict['type'] = default_ioc_type
    if ioc_type_key and ioc_dict.get(ioc_type_key):  # in case the user didn't specify a field type, we keep the default type
        ioc_dict['type'] = ioc_dict.get(ioc_type_key)

    ioc_dict['fields'] = {}
    if tags:
        ioc_dict['fields']['tags'] = tags
    if tlp_color:
        ioc_dict['fields']['trafficlightprotocol'] = tlp_color
    if enrichment_excluded:
        ioc_dict['enrichmentExcluded'] = enrichment_excluded

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
        LOG(f'command is {demisto.command()}')
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
        fetch_limit = arg_to_number(params.get('fetch_limit', FETCH_LIMIT))
        enrichment_excluded = (params.get('enrichmentExcluded', False)
                               or (params.get('tlp_color') == 'RED' and is_xsiam_or_xsoar_saas()))
        if not fetch_limit or fetch_limit > 10_000:
            raise DemistoException(f"Fetch limit must be between 1-10,000, got {fetch_limit}")
        query = params.get('es_query')
        api_id, api_key = extract_api_from_username_password(username, password)
        client = ElasticsearchClient(insecure, server, username, password, api_key, api_id, time_field, time_method,
                                     fetch_index, fetch_time, query, tags, tlp_color, enrichment_excluded)
        src_val = params.get('src_val')
        src_type = params.get('src_type')
        default_type = params.get('default_type')
        last_fetch = demisto.getLastRun().get('time')

        if demisto.command() == 'test-module':
            test_command(client, feed_type, src_val, src_type, default_type, time_method, time_field, fetch_time, query,
                         username, password, api_key, api_id)
        elif demisto.command() == 'fetch-indicators':
            fetch_indicators_command(client, feed_type, src_val, src_type, default_type, last_fetch, fetch_limit)
        elif demisto.command() == 'es-get-indicators':
            get_indicators_command(client, feed_type, src_val, src_type, default_type)
    except Exception as e:
        return_error(f"Failed executing {demisto.command()}.\nError message: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
