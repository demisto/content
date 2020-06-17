import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import Union, Optional, List, Dict, Tuple

import re
import types
import urllib3
from taxii2client import v20, v21
from taxii2client.common import TokenAuth
from taxii2client.exceptions import TAXIIServiceException

# disable insecure warnings
urllib3.disable_warnings()

TAXII_VER_2_0 = "2.0"
TAXII_VER_2_1 = "2.1"

DFLT_LIMIT_PER_FETCH = 1000

# Pattern Regexes - used to extract indicator type and value
INDICATOR_OPERATOR_VAL_FORMAT_PATTERN = r"(\w.*?{value}{operator})'(.*?)'"
INDICATOR_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(value="value", operator="=")
CIDR_ISSUBSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(value="value", operator="ISSUBSET")
CIDR_ISUPPERSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(value="value", operator="ISUPPERSET")
HASHES_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(value=r"hashes\..*?", operator="=")

TAXII_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

TAXII_TYPES_TO_CORTEX_TYPES = {
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "domain": FeedIndicatorType.Domain,
    "domain-name": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "md5": FeedIndicatorType.File,
    "sha-1": FeedIndicatorType.File,
    "sha-256": FeedIndicatorType.File,
    "file:hashes": FeedIndicatorType.File,
}

TAXII_TYPES_TO_CORTEX_CIDR_TYPES = {
    "ipv4-addr": FeedIndicatorType.CIDR,
    "ipv6-addr": FeedIndicatorType.IPv6CIDR,
}


class Taxii2FeedClient:
    def __init__(
        self,
        url,
        collection_to_fetch,
        proxies,
        verify,
        username=None,
        password=None,
        field_map=None,
    ):
        """
        TAXII 2 Client used to poll and parse indicators in XSOAR formar
        :param url: discovery service URL
        :param collection_to_fetch: Collection to fetch objects from
        :param proxies: proxies used in request
        :param verify: verify https
        :param username: username used for basic authentication OR api_key used for authentication
        :param password: password used for basic authentication
        :param field_map:
        """
        self.server = None
        self.api_root = None
        self.collections = None

        self.collection_to_fetch = collection_to_fetch
        self.base_url = url
        self.proxies = proxies
        self.verify = verify
        # TODO: add proper ssl error handling
        self.auth = None
        if username and password:
            self.auth = requests.auth.HTTPBasicAuth(username, password)
        # if only username is provided, assume it's an api key
        # TODO: add proper error in case not
        elif username:
            self.auth = TokenAuth(key=username)
        self.field_map = field_map if field_map else {}
        self.indicator_regexes = [
            re.compile(INDICATOR_EQUALS_VAL_PATTERN),
            re.compile(HASHES_EQUALS_VAL_PATTERN),
        ]
        self.cidr_regexes = [
            re.compile(CIDR_ISSUBSET_VAL_PATTERN),
            re.compile(CIDR_ISUPPERSET_VAL_PATTERN),
        ]

    def init_server(self, version=TAXII_VER_2_0):
        """
        Initializes a server in the requested version
        :param version: taxii version key (either 2.0 or 2.1)
        """
        server_url = urljoin(self.base_url)
        if version is TAXII_VER_2_0:
            self.server = v20.Server(
                server_url, verify=self.verify, auth=self.auth, proxies=self.proxies,
            )
        else:
            self.server = v21.Server(
                server_url, verify=self.verify, auth=self.auth, proxies=self.proxies,
            )

    def init_roots(self):
        """
        Initializes the api roots (used to get taxii server objects)
        """
        try:
            # try TAXII 2.0
            self.api_root = self.server.api_roots[0]
        except TAXIIServiceException:
            # switch to TAXII 2.1
            self.init_server(version=TAXII_VER_2_1)
            self.api_root = self.server.api_roots[0]

    def init_collections(self):
        """
        Collects available taxii collections
        """
        self.collections = [x for x in self.api_root.collections]  # type: ignore[attr-defined]

    def init_collection_to_fetch(self, collection_to_fetch=None):
        """
        Tries to initialize `collection_to_fetch` if possible
        """
        if collection_to_fetch is None and isinstance(self.collection_to_fetch, str):
            # self.collection_to_fetch will be changed from str -> Union[v20.Collection, v21.Collection]
            collection_to_fetch = self.collection_to_fetch
        if not self.collections:
            raise DemistoException(
                "No collection is available for this user, please make sure you entered the configuration correctly"
            )
        if collection_to_fetch:
            try:
                for collection in self.collections:
                    if collection.title == collection_to_fetch:
                        self.collection_to_fetch = collection
                        break
            except StopIteration:
                raise DemistoException(
                    "Could not find the provided Collection name in the available collections. "
                    "Please make sure you entered the name correctly."
                )

    def initialise(self):
        self.init_server()
        self.init_roots()
        self.init_collections()
        self.init_collection_to_fetch()

    def build_iterator(
        self, limit: int = -1, added_after: str = None
    ) -> List[Dict[str, str]]:
        """
        Polls the taxii server and builds a list of cortex indicators objects from the result
        :param limit: max amount of indicators to fetch
        :param added_after: poll objects that were added after this time. string in TAXII 2 time format
        :return: Cortex indicators list
        """
        if not isinstance(self.collection_to_fetch, (v20.Collection, v21.Collection)):
            raise DemistoException(
                "Could not find a collection to fetch from. "
                "Please make sure you provided a collection."
            )

        page_size = self.get_page_size(limit, limit)
        if page_size <= 0:
            return []
        envelope = self.poll_collection(page_size, added_after)
        indicators = self.extract_indicators_from_envelope_and_parse(envelope, limit)
        return indicators

    def extract_indicators_from_envelope_and_parse(
        self, envelope: Union[types.GeneratorType, Dict[str, str]], limit: int
    ) -> List[Dict[str, str]]:
        """
        Extract indicators from an 2.0 envelope generator, or 2.1 envelope (which then polls and repeats process)
        and parses them as cortex indicators
        :param envelope: envelope containing stix objects
        :param limit: max amount of indicators to fetch
        :return: Cortex indicators list
        """
        indicators = []
        obj_cnt = 0
        # TAXII 2.0
        if isinstance(envelope, types.GeneratorType):
            for sub_envelope in envelope:
                taxii_objects = sub_envelope.get("objects")
                if not taxii_objects:
                    # no fetched objects
                    break
                obj_cnt += len(taxii_objects)
                indicators.extend(
                    self.parse_indicators_list(
                        self.extract_indicators_from_taxii_objects(taxii_objects)
                    )
                )
                if len(indicators) >= limit:
                    break
        # TAXII 2.1
        else:
            cur_limit = limit
            taxii_objects = envelope.get("objects")
            obj_cnt += len(taxii_objects)
            indicators = self.parse_indicators_list(
                self.extract_indicators_from_taxii_objects(envelope.get("objects"))
            )
            while envelope.get("more", False) and cur_limit > 0:
                page_size = self.get_page_size(limit, cur_limit)
                envelope = self.poll_collection(page_size, envelope.get("next", ""))
                taxii_objects = envelope.get("objects")
                obj_cnt += len(taxii_objects)
                cur_limit -= len(envelope)
                indicators.extend(
                    self.parse_indicators_list(
                        self.extract_indicators_from_taxii_objects(taxii_objects)
                    )
                )
        demisto.debug(
            f"TAXII 2 Feed has extracted {len(indicators)} indicators / {obj_cnt} taxii objects"
        )
        return indicators[:limit]

    def poll_collection(
        self, page_size: int, added_after: Optional[str] = None
    ) -> Union[types.GeneratorType, Dict[str, str]]:
        """
        Polls a taxii collection
        :param page_size: size of the request page
        :param (optional) added_after: fetch taxii objects after this time (taxii time format)
        """
        get_objects = self.collection_to_fetch.get_objects
        if isinstance(self.collection_to_fetch, v20.Collection):
            envelope = v20.as_pages(
                get_objects, per_request=page_size, added_after=added_after
            )
        else:
            envelope = get_objects(limit=page_size, added_after=added_after)
        return envelope

    @staticmethod
    def get_page_size(max_limit: int, cur_limit: int) -> int:
        """
        Get a page size given the limit on entries `max_limit` and the limit on the current poll
        :param max_limit: max amount of entries allowed overall
        :param cur_limit: max amount of entries allowed in a page
        :return: page size
        """
        return (
            min(DFLT_LIMIT_PER_FETCH, cur_limit)
            if max_limit > -1
            else DFLT_LIMIT_PER_FETCH
        )

    @staticmethod
    def extract_indicators_from_taxii_objects(
        taxii_objs: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """
        Extracts indicators from taxii objects
        :param taxii_objs: taxii objects
        :return: indicators in json format
        """
        indicators_objs = [
            item for item in taxii_objs if item.get("type") == "indicator"
        ]  # retrieve only indicators

        return indicators_objs

    def parse_indicators_list(
        self, indicators_objs: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """
        Parses a list of indicator objects
        :param indicators_objs: indicator objects
        :return: Parsed list of indicators
        """
        indicators = []
        if indicators_objs:
            for indicator_obj in indicators_objs:
                indicators.extend(self.parse_single_indicator(indicator_obj))
        return indicators

    def parse_single_indicator(
        self, indicator_obj: Dict[str, str]
    ) -> List[Dict[str, str]]:
        """
        Parses a single indicator object
        :param indicator_obj: indicator object
        :return: list of indicators extracted from the object in cortex format
        """
        field_map = self.field_map if self.field_map else {}
        pattern = indicator_obj.get("pattern")
        indicators = []
        if pattern:
            # this is done in case the server doesn't properly space the operator,
            # supported indicators have no spaces, so this action shouldn't affect extracted values
            trimmed_pattern = pattern.replace(" ", "")

            indicator_groups = self.extract_indicator_groups_from_pattern(
                trimmed_pattern, self.indicator_regexes
            )
            indicators.extend(
                self.get_indicators_from_indicator_groups(
                    indicator_groups,
                    indicator_obj,
                    TAXII_TYPES_TO_CORTEX_TYPES,
                    field_map,
                )
            )

            cidr_groups = self.extract_indicator_groups_from_pattern(
                trimmed_pattern, self.cidr_regexes
            )
            indicators.extend(
                self.get_indicators_from_indicator_groups(
                    cidr_groups,
                    indicator_obj,
                    TAXII_TYPES_TO_CORTEX_CIDR_TYPES,
                    field_map,
                )
            )

        return indicators

    def get_indicators_from_indicator_groups(
        self,
        indicator_groups: List[Tuple[str, str]],
        indicator_obj: Dict[str, str],
        indicator_types: Dict[str, str],
        field_map: Dict[str, str],
    ) -> List[Dict[str, str]]:
        """
        Get indicators from indicator regex groups
        :param indicator_groups: caught regex group in pattern of: [`type`, `indicator`]
        :param indicator_obj: taxii indicator object
        :param indicator_types: supported indicator types -> cortex types
        :param field_map: map used to create fields entry
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
                        indicator = self.create_indicator(
                            indicator_obj, type_, value, field_map
                        )
                        indicators.append(indicator)
                        break
        return indicators

    def extract_indicator_groups_from_pattern(
        self, pattern: str, regexes: List
    ) -> List[Tuple[str, str]]:
        """
        Extracts indicator [`type`, `indicator`] groups from pattern
        :param pattern: stix pattern
        :param regexes: regexes to run to pattern
        :return: extracted indicators list from pattern
        """
        groups = []
        for regex in regexes:
            find_result = regex.findall(pattern)
            if find_result:
                groups.extend(find_result)
        return groups

    @staticmethod
    def create_indicator(indicator_obj, type_, value, field_map):
        """
        Create a cortex indicator from a stix indicator
        :param indicator_obj: rawJSON value of the indicator
        :param type_: cortex type of the indicator
        :param value: indicator value
        :param field_map: field map used for mapping fields
        :return: Cortex indicator
        """
        indicator = {
            "value": value,
            "type": type_,
            "rawJSON": indicator_obj,
        }
        fields = {}
        for field_name, field_path in field_map.items():
            if field_path in indicator_obj:
                fields[field_name] = indicator_obj.get(field_path)
        if fields:
            indicator["fields"] = fields
        return indicator
