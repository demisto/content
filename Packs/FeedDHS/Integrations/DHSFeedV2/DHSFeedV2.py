import copy
from typing import Tuple

import demistomock as demisto
from CommonServerPython import *
from TAXII2ApiModule import Taxii2FeedClient, TAXII_TIME_FORMAT, DFLT_LIMIT_PER_REQUEST, INDICATOR_EQUALS_VAL_PATTERN, \
    HASHES_EQUALS_VAL_PATTERN, STIX_2_TYPES_TO_CORTEX_TYPES, CIDR_ISSUBSET_VAL_PATTERN, CIDR_ISUPPERSET_VAL_PATTERN, \
    STIX_2_TYPES_TO_CORTEX_CIDR_TYPES, THREAT_INTEL_TYPE_TO_DEMISTO_TYPES

''' CONSTANTS '''

COMPLEX_OBSERVATION_MODE_SKIP = 'Skip indicators with more than a single observation'

HEADERS = {
    "Accept": "application/taxii+json;version=2.1",
    "Content-Type": "application/taxii+json"
}

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, url, verify, proxy, certificate, key, headers, api_root, tags, objects_to_fetch='', tlp_color='',
                 skip_complex_mode=True, limit_per_request=DFLT_LIMIT_PER_REQUEST):
        super().__init__(base_url=url, verify=verify, proxy=proxy, headers=headers)
        self._cert = (Taxii2FeedClient.build_certificate(certificate), Taxii2FeedClient.build_certificate(key))
        self._api_root = api_root
        self._limit_per_request = limit_per_request

        self._tags = tags
        self._objects_to_fetch = objects_to_fetch
        self._tlp_color = tlp_color
        self._skip_complex_mode = skip_complex_mode

        self._id_to_object: Dict[str, Any] = {}
        self.last_fetched_indicator_modified = None

    def request_production_collection_endpoints(self):
        """
        Returns the reachable API roots.
        """
        response = self._http_request('GET', 'taxii2/', cert=self._cert)
        # response fields: title, api_roots
        # optional response fields: description, contact, default

        return [str(api_root_url).split('/')[-2]
                for api_root_url in response.get('api_roots', [])]

    def request_public_collections_info(self):
        response = self._http_request('GET', f'{self._api_root}/collections/', cert=self._cert)

        return response.get('collections', [])

    def request_public_objects_info(self, public_collection_id: str, added_after: str = None,
                                    limit: int = None, next_page: Union[str, int] = None):
        params = assign_params(added_after=added_after,
                               limit=get_page_size(limit or -1, self._limit_per_request),
                               next=next_page,
                               objects_types=self._objects_to_fetch)
        if 'objects_types' in params:
            params['match[type]'] = params.pop('objects_types')

        response = self._http_request('GET', f'{self._api_root}/collections/{public_collection_id}/objects/',
                                      params=params, cert=self._cert)

        return response

    def request_public_objects_info_all_pages(self, public_collection_id: str, added_after: str = None, limit: int = -1):
        indicators: list = []
        relationships_list: List[Dict[str, Any]] = []

        response = {'more': True}
        while response.get("more", False) and not reached_limit(limit, len(indicators)):
            demisto.debug(f'entered loop with next={response.get("next")}')
            response = self.request_public_objects_info(public_collection_id, added_after=added_after, limit=limit,
                                                        next_page=response.get('next'))
            demisto.debug(f'in request_public_objects_info_all_pages, request_public_objects_info returned {response=}')
            new_indicators, new_relationships = self._parse_objects(response, limit)
            indicators.extend(new_indicators)
            relationships_list.extend(new_relationships)

        if relationships_list:
            indicators.extend(self._parse_relationships(relationships_list))
        return indicators

    def _parse_objects(self, response, limit):
        indicators: list = []
        relationships_list: List[Dict[str, Any]] = []

        stix_objects = response.get('objects', [])
        for obj in stix_objects:
            obj_type = obj.get('type')
            if obj_type == "relationship":
                relationships_list.extend(stix_objects)
                continue

            self._id_to_object[obj.get('id')] = obj
            if result := self._parse_indicator(obj):
                indicators.extend(result)
                self._update_last_modified_indicator_date(obj.get('modified'))

            if reached_limit(limit, len(indicators)):
                break

        return indicators, relationships_list

    def _parse_indicator(self, indicator_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses a single indicator object
        :param indicator_obj: indicator object
        :return: indicators extracted from the indicator object in cortex format
        """
        pattern = indicator_obj.get("pattern")
        indicators = []
        if pattern:
            # this is done in case the server doesn't properly space the operator,
            # supported indicators have no spaces, so this action shouldn't affect extracted values
            trimmed_pattern = pattern.replace(" ", "")

            indicator_groups = Taxii2FeedClient.extract_indicator_groups_from_pattern(trimmed_pattern,
                                                                                      [re.compile(INDICATOR_EQUALS_VAL_PATTERN),
                                                                                       re.compile(HASHES_EQUALS_VAL_PATTERN)])

            indicators.extend(
                self._get_indicators_from_indicator_groups(indicator_groups, indicator_obj, STIX_2_TYPES_TO_CORTEX_TYPES))

            cidr_groups = Taxii2FeedClient.extract_indicator_groups_from_pattern(trimmed_pattern,
                                                                                 [re.compile(CIDR_ISSUBSET_VAL_PATTERN),
                                                                                  re.compile(CIDR_ISUPPERSET_VAL_PATTERN)])
            indicators.extend(
                self._get_indicators_from_indicator_groups(cidr_groups, indicator_obj, STIX_2_TYPES_TO_CORTEX_CIDR_TYPES))

        return indicators

    def _get_indicators_from_indicator_groups(self, indicator_groups: List[Tuple[str, str]], indicator_obj: Dict[str, str],
                                              indicator_types: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Get indicators from indicator regex groups
        :param indicator_groups: caught regex group in pattern of: [`type`, `indicator`]
        :param indicator_obj: taxii indicator object
        :param indicator_types: supported indicator types -> cortex types
        :return: Indicators list
        """
        indicators = []
        if indicator_groups:
            for term in indicator_groups:
                for taxii_type in indicator_types.keys():
                    # term should be list with 2 argument parsed with regex - [`type`, `indicator`]
                    if len(term) == 2 and taxii_type in term[0]:
                        type_ = indicator_types[taxii_type]
                        value = term[1]
                        indicator = self._create_indicator(indicator_obj, type_, value)
                        indicators.append(indicator)
                        break
        if self._skip_complex_mode and len(indicators) > 1:
            # we managed to pull more than a single indicator - indicating complex relationship
            return []
        return indicators

    def _create_indicator(self, indicator_obj, type_, value):
        """
        Create a cortex indicator from a stix indicator
        :param indicator_obj: rawJSON value of the indicator
        :param type_: cortex type of the indicator
        :param value: indicator value
        :return: Cortex indicator
        """
        ioc_obj_copy = copy.deepcopy(indicator_obj)
        ioc_obj_copy["value"] = value
        ioc_obj_copy["type"] = type_
        indicator = {
            "value": value,
            "type": type_,
            "rawJSON": ioc_obj_copy,
        }
        fields = {}
        tags = list(self._tags)
        # create tags from labels:
        for label in ioc_obj_copy.get("labels", []):
            tags.append(label)

        # add description if able
        if "description" in ioc_obj_copy:
            fields["description"] = ioc_obj_copy["description"]

        # union of tags and labels
        if "tags" in fields:
            field_tag = fields.get("tags")
            if isinstance(field_tag, list):
                tags.extend(field_tag)
            else:
                tags.append(field_tag)

        fields["tags"] = tags

        if self._tlp_color and not fields.get('trafficlightprotocol'):
            fields["trafficlightprotocol"] = self._tlp_color

        indicator["fields"] = fields
        return indicator

    def _update_last_modified_indicator_date(self, indicator_modified_str: str):
        if not indicator_modified_str:
            return
        if self.last_fetched_indicator_modified is None:
            self.last_fetched_indicator_modified = indicator_modified_str  # type: ignore[assignment]
        else:
            last_datetime = Taxii2FeedClient.stix_time_to_datetime(self.last_fetched_indicator_modified)
            indicator_created_datetime = Taxii2FeedClient.stix_time_to_datetime(indicator_modified_str)
            if indicator_created_datetime > last_datetime:
                self.last_fetched_indicator_modified = indicator_modified_str

    def _parse_relationships(self, relationships_lst: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse the Relationships objects retrieved from the feed.

        Returns:
            A list of processed relationships an indicator object.
        """
        relationships_list = []
        for relationships_object in relationships_lst:
            relationship_type = relationships_object.get('relationship_type')
            if relationship_type not in EntityRelationship.Relationships.RELATIONSHIPS_NAMES.keys():
                if relationship_type == 'indicates':
                    relationship_type = 'indicated-by'
                else:
                    demisto.debug(f"Invalid relation type: {relationship_type}")
                    continue

            a_threat_intel_type = relationships_object.get('source_ref', '').split('--')[0]
            a_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(a_threat_intel_type, '')  # type: ignore
            if a_threat_intel_type == 'indicator':
                id = relationships_object.get('source_ref', '')
                a_type = Taxii2FeedClient.get_ioc_type(id, self._id_to_object)

            b_threat_intel_type = relationships_object.get('target_ref', '').split('--')[0]
            b_type = THREAT_INTEL_TYPE_TO_DEMISTO_TYPES.get(b_threat_intel_type, '')  # type: ignore
            if b_threat_intel_type == 'indicator':
                b_type = Taxii2FeedClient.get_ioc_type(relationships_object.get('target_ref', ''), self._id_to_object)

            if not a_type or not b_type:
                continue

            mapping_fields = {
                'lastseenbysource': relationships_object.get('modified'),
                'firstseenbysource': relationships_object.get('created'),
            }

            entity_a = Taxii2FeedClient.get_ioc_value(relationships_object.get('source_ref'), self._id_to_object)
            entity_b = Taxii2FeedClient.get_ioc_value(relationships_object.get('target_ref'), self._id_to_object)

            entity_relation = EntityRelationship(name=relationship_type,
                                                 entity_a=entity_a,
                                                 entity_a_type=a_type,
                                                 entity_b=entity_b,
                                                 entity_b_type=b_type,
                                                 fields=mapping_fields)
            if relation_indicator := entity_relation.to_indicator():
                relationships_list.append(relation_indicator)

        dummy_indicator = {
            "value": "$$DummyIndicator$$",
            "relationships": relationships_list
        }
        return [dummy_indicator] if relationships_list else []


''' NEW COMMAND FUNCTIONS '''


def get_collection_id_by_name(collections, name):
    for collection in collections:
        if collection.get('title') == name:
            return collection.get('id')


def get_page_size(limit, limit_per_request):
    return min(limit_per_request, limit) if limit > -1 else limit_per_request


def reached_limit(limit: int, element_count: int):
    demisto.debug(f'{element_count=}')
    return element_count >= limit > -1


''' COMMAND FUNCTIONS '''


def command_test_module(client: Client, default_api_root: str, is_fetch: bool = False, collection_to_fetch: str = None):
    try:
        collections = client.request_public_collections_info()
        if not collections:
            return 'Could not connect to server.'

        if is_fetch and collection_to_fetch:
            if not get_collection_id_by_name(collections, collection_to_fetch):
                return f'The given "Collection Name To Fetch Indicators From" ({collection_to_fetch}) ' \
                       f'is not one of the reachable collections. Available collections are: ' \
                       f'{",".join([collection.get("title") for collection in collections])}.'
        return 'ok'

    except DemistoException as de:
        if de.res.status_code in [403, 404]:
            api_roots = client.request_production_collection_endpoints()
            if default_api_root not in api_roots:
                return f'The given "Default API Root" ({default_api_root}) is not one of the reachable API roots. ' \
                       f'Available API roots are: {",".join(api_roots)}.'
            else:
                raise
        else:
            raise


def fetch_indicators_command(client: Client, collection_to_fetch, limit: int, last_run_ctx: dict,
                             initial_interval: str = '24 hours') \
        -> Tuple[list, dict]:
    """
    Fetch indicators from TAXII 2 server
    :param client: Taxii2FeedClient
    :param limit: upper limit of indicators to fetch
    :param last_run_ctx: last run dict with {collection_id: last_run_time string}
    :param initial_interval: initial interval in human readable format
    :return: indicators in cortex TIM format, updated last_run_ctx
    """
    initial_interval: datetime = dateparser.parse(initial_interval or '24 hours',
                                                  date_formats=[TAXII_TIME_FORMAT])  # type: ignore[assignment]
    limit = limit or -1

    if collection_to_fetch:
        collection_id = get_collection_id_by_name(client.request_public_collections_info(), collection_to_fetch)
        indicators, last_run_ctx = fetch_one_collection(client, collection_id, limit, initial_interval, last_run_ctx)
    else:
        indicators, last_run_ctx = fetch_all_collections(client, limit, initial_interval, last_run_ctx)

    return indicators, last_run_ctx


def fetch_one_collection(client: Client, collection_id: str, limit: int, initial_interval: Union[str, datetime],
                         last_run_ctx: Optional[dict] = None):
    demisto.debug('in fetch_one_collection')
    last_fetch_time = last_run_ctx.get(collection_id) if last_run_ctx else None
    initial_interval_str = initial_interval.strftime(TAXII_TIME_FORMAT) \
        if isinstance(initial_interval, datetime) \
        else initial_interval
    added_after = last_fetch_time or initial_interval_str

    indicators = client.request_public_objects_info_all_pages(public_collection_id=collection_id, added_after=added_after,
                                                              limit=limit)
    if last_run_ctx is not None:  # in case we got {}, we want to set it because we are in fetch incident run
        last_run_ctx[collection_id] = client.last_fetched_indicator_modified \
            if client.last_fetched_indicator_modified \
            else added_after

    return indicators, last_run_ctx


def fetch_all_collections(client: Client, limit: int, initial_interval: Union[str, datetime],
                          last_run_ctx: Optional[dict] = None):
    indicators: list = []
    demisto.debug('in fetch_all_collections')
    for collection in client.request_public_collections_info():
        fetched_iocs, last_run_ctx = fetch_one_collection(client, collection.get('id'), limit, initial_interval, last_run_ctx)
        indicators.extend(fetched_iocs)

        if limit >= 0:
            limit -= len(fetched_iocs)
            if limit <= 0:
                break
        demisto.debug(f'{limit=}')

    return indicators, last_run_ctx


def get_indicators_command(client: Client,
                           collection_to_fetch=None,
                           limit='10',
                           added_after='20 days',
                           raw='false') -> Union[CommandResults, Dict[str, List[Optional[str]]]]:
    limit = arg_to_number(limit) or 10
    added_after: datetime = dateparser.parse(added_after or '20 days',
                                             date_formats=[TAXII_TIME_FORMAT])  # type: ignore[assignment]
    added_after_str: str = added_after.strftime(TAXII_TIME_FORMAT)
    raw = argToBoolean(raw) or False

    if collection_to_fetch:
        collection_id = get_collection_id_by_name(client.request_public_collections_info(), collection_to_fetch)
        indicators = client.request_public_objects_info_all_pages(public_collection_id=collection_id,
                                                                  added_after=added_after_str, limit=limit)
    else:
        indicators, _ = fetch_all_collections(client, limit, added_after_str)

    if raw:
        return {'indicators': [x.get('rawJSON') for x in indicators]}

    return CommandResults(
        readable_output=f'Found {len(indicators)} results:\n' + tableToMarkdown(name='DHS Indicators', t=indicators,
                                                                                headers=['value', 'type'], removeNull=True),
        outputs_prefix='DHS.Indicators',
        outputs_key_field='value',
        outputs=indicators,
        raw_response=indicators,
    )


def get_limited_indicators_command(client: Client,
                                   collection_to_fetch='Public Collection',
                                   limit='10',
                                   added_after='20 days',
                                   raw='false') -> Union[CommandResults, Dict[str, List[Optional[str]]]]:
    limit = arg_to_number(limit) or 10
    added_after: datetime = dateparser.parse(added_after or '20 days',
                                             date_formats=[TAXII_TIME_FORMAT])  # type: ignore[assignment]
    added_after_str: str = added_after.strftime(TAXII_TIME_FORMAT)
    raw = argToBoolean(raw) or False

    collection_id = get_collection_id_by_name(client.request_public_collections_info(), collection_to_fetch)
    response = client.request_public_objects_info(public_collection_id=collection_id, added_after=added_after_str, limit=limit)
    demisto.debug(f'{response=}')
    indicators, relationships = client._parse_objects(response, limit)
    if relationships:
        indicators.extend(client._parse_relationships(relationships))

    if raw:
        return {'indicators': [x.get('rawJSON') for x in indicators]}

    return CommandResults(
        readable_output=f'Found {len(indicators)} results:\n' + tableToMarkdown(name='DHS Indicators', t=indicators,
                                                                                headers=['value', 'type'], removeNull=True),
        outputs_prefix='DHS.Indicators',
        outputs_key_field='value',
        outputs=indicators,
        raw_response=indicators,
    )


def get_collections_command(client: Client) -> CommandResults:
    """
    Get the available collections in the DHS server
    """
    response = client.request_public_collections_info()
    # response fields: id, title, can_read, can_write
    # optional response fields: description, alias, media_types
    collections = [{'Name': collection.get('title'), 'ID': collection.get('id')}
                   for collection in response]

    return CommandResults(
        readable_output=tableToMarkdown('DHS Server Collections', t=collections, headers=['Name', 'ID']),
        outputs_prefix='DHS.Collections',
        outputs_key_field='ID',
        outputs=collections,
    )


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    params = demisto.params()
    url = params.get('url', 'https://ais2.cisa.dhs.gov/')
    key = params.get('key', {}).get('password')
    certificate = params.get('certificate')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    collection_to_fetch = params.get('collection_to_fetch')
    skip_complex_mode = COMPLEX_OBSERVATION_MODE_SKIP == params.get('observation_operator_mode')
    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color', '')

    initial_interval = params.get('initial_interval', '24 hours')
    limit = arg_to_number(params.get('limit')) or -1
    limit_per_request = arg_to_number(params.get('limit_per_request')) or DFLT_LIMIT_PER_REQUEST
    default_api_root = params.get('default_api_root', 'public')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(url=urljoin(url),
                        verify=verify_certificate,
                        proxy=proxy,
                        certificate=certificate,
                        key=key,
                        headers=HEADERS,
                        api_root=default_api_root,
                        tags=feed_tags,
                        objects_to_fetch='indicator,relationship',
                        tlp_color=tlp_color,
                        skip_complex_mode=skip_complex_mode,
                        limit_per_request=limit_per_request,
                        )

        if command == 'test-module':
            return_results(command_test_module(client, default_api_root, argToBoolean(params.get('feed')), collection_to_fetch))

        elif command == 'fetch-indicators':
            last_run_indicators = demisto.getLastRun()
            indicators, last_run_indicators = fetch_indicators_command(client,
                                                                       collection_to_fetch,
                                                                       limit,
                                                                       last_run_indicators,
                                                                       initial_interval)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

            demisto.setLastRun(last_run_indicators)

        elif command == 'dhs-get-indicators':
            return_results(get_indicators_command(client, collection_to_fetch, **demisto.args()))

        elif command == 'dhs-get-limited-indicators':
            return_results(get_limited_indicators_command(client, collection_to_fetch, **demisto.args()))

        elif command == 'dhs-get-collections':
            return_results(get_collections_command(client))

        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as error:
        error_msg = str(error)
        if isinstance(error, requests.exceptions.SSLError):
            error_msg = 'Encountered an HTTPS certificate error. This error can be ignored by enabling ' \
                        '"Trust any certificate (not secure)" in the instance configuration.'
        elif isinstance(error, requests.HTTPError):
            error_msg = 'Encountered an HTTP error. Please check your certificate and key, and that you are trying to reach a ' \
                        'valid URL and API root. If this occurs when the test works, change the "limit" in the instance ' \
                        'configuration or command argument.'
        return_error(error_msg, error)


''' ENTRY POINT '''

if __name__ in ('__main__', 'builtins'):
    main()
