import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Union, Optional, List, Dict, Tuple
from requests.sessions import merge_setting, CaseInsensitiveDict
import re
import copy
import types
import urllib3
from taxii2client import v20, v21
from taxii2client.common import TokenAuth, _HTTPConnection

# disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
TAXII_VER_2_0 = "2.0"
TAXII_VER_2_1 = "2.1"

DFLT_LIMIT_PER_REQUEST = 100
API_USERNAME = "_api_token_key"
HEADER_USERNAME = "_header:"

ERR_NO_COLL = "No collection is available for this user, please make sure you entered the configuration correctly"

# Pattern Regexes - used to extract indicator type and value
INDICATOR_OPERATOR_VAL_FORMAT_PATTERN = r"(\w.*?{value}{operator})'(.*?)'"
INDICATOR_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="value", operator="="
)
CIDR_ISSUBSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="value", operator="ISSUBSET"
)
CIDR_ISUPPERSET_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value="value", operator="ISUPPERSET"
)
HASHES_EQUALS_VAL_PATTERN = INDICATOR_OPERATOR_VAL_FORMAT_PATTERN.format(
    value=r"hashes\..*?", operator="="
)

TAXII_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
TAXII_TIME_FORMAT_NO_MS = "%Y-%m-%dT%H:%M:%SZ"

STIX_2_TYPES_TO_CORTEX_TYPES = {
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

STIX_2_TYPES_TO_CORTEX_CIDR_TYPES = {
    "ipv4-addr": FeedIndicatorType.CIDR,
    "ipv6-addr": FeedIndicatorType.IPv6CIDR,
}


class Taxii2FeedClient:
    def __init__(
        self,
        url: str,
        collection_to_fetch,
        proxies,
        verify: bool,
        skip_complex_mode: bool = False,
        username: Optional[str] = None,
        password: Optional[str] = None,
        field_map: Optional[dict] = None,
        tags: Optional[list] = None,
        limit_per_request: int = DFLT_LIMIT_PER_REQUEST,
    ):
        """
        TAXII 2 Client used to poll and parse indicators in XSOAR formar
        :param url: discovery service URL
        :param collection_to_fetch: Collection to fetch objects from
        :param proxies: proxies used in request
        :param skip_complex_mode: if set to True will skip complex observations
        :param verify: verify https
        :param username: username used for basic authentication OR api_key used for authentication
        :param password: password used for basic authentication
        :param field_map: map used to create fields entry ({field_name: field_value})
        :param tags: custom tags to be added to the created indicator
        :param limit_per_request: Limit the objects requested per poll request
        """
        self._conn = None
        self.server = None
        self.api_root = None
        self.collections = None
        self.last_fetched_indicator__modified = None

        self.collection_to_fetch = collection_to_fetch
        self.skip_complex_mode = skip_complex_mode
        if not limit_per_request:
            limit_per_request = DFLT_LIMIT_PER_REQUEST
        self.limit_per_request = limit_per_request

        self.base_url = url
        self.proxies = proxies
        self.verify = verify

        self.auth = None
        self.auth_header = None
        self.auth_key = None
        if username and password:
            # authentication methods:
            # 1. API Token
            # 2. Authentication Header
            # 3. Basic
            if username == API_USERNAME:
                self.auth = TokenAuth(key=password)
            elif username.startswith(HEADER_USERNAME):
                self.auth_header = username.split(HEADER_USERNAME)[1]
                self.auth_key = password
            else:
                self.auth = requests.auth.HTTPBasicAuth(username, password)

        self.field_map = field_map if field_map else {}
        self.tags = tags if tags else []
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
        self._conn = _HTTPConnection(
            verify=self.verify, proxies=self.proxies, version=version, auth=self.auth
        )
        if self.auth_header:
            # add auth_header to the session object
            self._conn.session.headers = (  # type: ignore[attr-defined]
                merge_setting(
                    self._conn.session.headers,  # type: ignore[attr-defined]
                    {self.auth_header: self.auth_key},
                    dict_class=CaseInsensitiveDict,
                ),
            )
        if version is TAXII_VER_2_0:
            self.server = v20.Server(
                server_url, verify=self.verify, proxies=self.proxies, conn=self._conn,
            )
        else:
            self.server = v21.Server(
                server_url, verify=self.verify, proxies=self.proxies, conn=self._conn,
            )

    def init_roots(self):
        """
        Initializes the api roots (used to get taxii server objects)
        """
        if not self.server:
            self.init_server()
        try:
            # try TAXII 2.0
            self.api_root = self.server.api_roots[0]  # type: ignore[union-attr, attr-defined]
            # override _conn - api_root isn't initialized with the right _conn
            self.api_root._conn = self._conn  # type: ignore[attr-defined]
        # (TAXIIServiceException, HTTPError) should suffice, but sometimes it raises another type of HTTPError
        except Exception as e:
            if "406 Client Error" not in str(e):
                raise e
            # switch to TAXII 2.1
            self.init_server(version=TAXII_VER_2_1)
            self.api_root = self.server.api_roots[0]  # type: ignore[union-attr, attr-defined]
            # override _conn - api_root isn't initialized with the right _conn
            self.api_root._conn = self._conn  # type: ignore[attr-defined]

    def init_collections(self):
        """
        Collects available taxii collections
        """
        self.collections = [x for x in self.api_root.collections]  # type: ignore[union-attr, attr-defined, assignment]

    def init_collection_to_fetch(self, collection_to_fetch=None):
        """
        Tries to initialize `collection_to_fetch` if possible
        """
        if collection_to_fetch is None and isinstance(self.collection_to_fetch, str):
            # self.collection_to_fetch will be changed from str -> Union[v20.Collection, v21.Collection]
            collection_to_fetch = self.collection_to_fetch
        if not self.collections:
            raise DemistoException(ERR_NO_COLL)
        if collection_to_fetch:
            collection_found = False
            for collection in self.collections:
                if collection.title == collection_to_fetch:
                    self.collection_to_fetch = collection
                    collection_found = True
                    break
            if not collection_found:
                raise DemistoException(
                    "Could not find the provided Collection name in the available collections. "
                    "Please make sure you entered the name correctly."
                )

    def initialise(self):
        self.init_server()
        self.init_roots()
        self.init_collections()
        self.init_collection_to_fetch()

    def build_iterator(self, limit: int = -1, **kwargs) -> List[Dict[str, str]]:
        """
        Polls the taxii server and builds a list of cortex indicators objects from the result
        :param limit: max amount of indicators to fetch
        :return: Cortex indicators list
        """
        if not isinstance(self.collection_to_fetch, (v20.Collection, v21.Collection)):
            raise DemistoException(
                "Could not find a collection to fetch from. "
                "Please make sure you provided a collection."
            )
        if limit is None:
            limit = -1

        page_size = self.get_page_size(limit, limit)
        if page_size <= 0:
            return []
        envelope = self.poll_collection(page_size, **kwargs)
        indicators = self.extract_indicators_from_envelope_and_parse(envelope, limit)
        return indicators

    def extract_indicators_from_envelope_and_parse(
        self, envelope: Union[types.GeneratorType, Dict[str, str]], limit: int = -1
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
                stix_objects = sub_envelope.get("objects")
                if not stix_objects:
                    # no fetched objects
                    break
                obj_cnt += len(stix_objects)
                indicators.extend(
                    self.parse_indicators_list(
                        self.extract_indicators_from_stix_objects(stix_objects)
                    )
                )
                if 0 < limit <= len(indicators):
                    break
        # TAXII 2.1
        elif isinstance(envelope, Dict):
            cur_limit = limit
            stix_objects = envelope.get("objects")
            obj_cnt += len(stix_objects)
            indicators_list = self.extract_indicators_from_stix_objects(stix_objects)
            indicators = self.parse_indicators_list(indicators_list)
            while envelope.get("more", False):
                page_size = self.get_page_size(limit, cur_limit)
                envelope = self.collection_to_fetch.get_objects(
                    limit=page_size, next=envelope.get("next", "")
                )
                if isinstance(envelope, Dict):
                    stix_objects = envelope.get("objects")
                    obj_cnt += len(stix_objects)
                    extracted_iocs = self.extract_indicators_from_stix_objects(
                        stix_objects
                    )
                    parsed_iocs = self.parse_indicators_list(extracted_iocs)
                    indicators.extend(parsed_iocs)

                    if limit > -1:
                        cur_limit -= len(envelope)  # type: ignore
                        if cur_limit < 0:
                            break
                else:
                    raise DemistoException(
                        "Error: TAXII 2 client received the following response while requesting "
                        f"indicators: {str(envelope)}\n\nExpected output is json"
                    )
        demisto.debug(
            f"TAXII 2 Feed has extracted {len(indicators)} indicators / {obj_cnt} stix objects"
        )
        if limit > -1:
            return indicators[:limit]
        return indicators

    def poll_collection(
        self, page_size: int, **kwargs
    ) -> Union[types.GeneratorType, Dict[str, str]]:
        """
        Polls a taxii collection
        :param page_size: size of the request page
        """
        get_objects = self.collection_to_fetch.get_objects
        if isinstance(self.collection_to_fetch, v20.Collection):
            envelope = v20.as_pages(get_objects, per_request=page_size, **kwargs)
        else:
            envelope = get_objects(limit=page_size, **kwargs)
        return envelope

    def get_page_size(self, max_limit: int, cur_limit: int) -> int:
        """
        Get a page size given the limit on entries `max_limit` and the limit on the current poll
        :param max_limit: max amount of entries allowed overall
        :param cur_limit: max amount of entries allowed in a page
        :return: page size
        """
        return (
            min(self.limit_per_request, cur_limit)
            if max_limit > -1
            else self.limit_per_request
        )

    @staticmethod
    def extract_indicators_from_stix_objects(
        stix_objs: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """
        Extracts indicators from taxii objects
        :param stix_objs: taxii objects
        :return: indicators in json format
        """
        indicators_objs = [
            item for item in stix_objs if item.get("type") == "indicator"
        ]  # retrieve only indicators

        return indicators_objs

    def parse_indicators_list(
        self, indicators_objs: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """
        Parses a list of indicator objects, and updates the client.latest_fetched_indicator_created
        :param indicators_objs: indicator objects
        :return: Parsed list of indicators
        """
        indicators = []
        if indicators_objs:
            for indicator_obj in indicators_objs:
                indicators.extend(self.parse_single_indicator(indicator_obj))
                indicator_modified_str = indicator_obj.get("modified")
                if self.last_fetched_indicator__modified is None:
                    self.last_fetched_indicator__modified = indicator_modified_str  # type: ignore[assignment]
                else:
                    last_datetime = self.stix_time_to_datetime(
                        self.last_fetched_indicator__modified
                    )
                    indicator_created_datetime = self.stix_time_to_datetime(
                        indicator_modified_str
                    )
                    if indicator_created_datetime > last_datetime:
                        self.last_fetched_indicator__modified = indicator_modified_str
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
                    STIX_2_TYPES_TO_CORTEX_TYPES,
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
                    STIX_2_TYPES_TO_CORTEX_CIDR_TYPES,
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
        :param field_map: map used to create fields entry ({field_name: field_value})
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
        if self.skip_complex_mode and len(indicators) > 1:
            # we managed to pull more than a single indicator - indicating complex relationship
            return []
        return indicators

    def create_indicator(self, indicator_obj, type_, value, field_map):
        """
        Create a cortex indicator from a stix indicator
        :param indicator_obj: rawJSON value of the indicator
        :param type_: cortex type of the indicator
        :param value: indicator value
        :param field_map: field map used for mapping fields ({field_name: field_value})
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
        tags = list(self.tags)
        # create tags from labels:
        for label in ioc_obj_copy.get("labels", []):
            tags.append(label)

        # add description if able
        if "description" in ioc_obj_copy:
            fields["description"] = ioc_obj_copy["description"]

        # add field_map fields
        for field_name, field_path in field_map.items():
            if field_path in ioc_obj_copy:
                fields[field_name] = ioc_obj_copy.get(field_path)

        # union of tags and labels
        if "tags" in fields:
            field_tag = fields.get("tags")
            if isinstance(field_tag, list):
                tags.extend(field_tag)
            else:
                tags.append(field_tag)

        fields["tags"] = tags
        indicator["fields"] = fields
        return indicator

    @staticmethod
    def extract_indicator_groups_from_pattern(
        pattern: str, regexes: List
    ) -> List[Tuple[str, str]]:
        """
        Extracts indicator [`type`, `indicator`] groups from pattern
        :param pattern: stix pattern
        :param regexes: regexes to run to pattern
        :return: extracted indicators list from pattern
        """
        groups: List[Tuple[str, str]] = []
        for regex in regexes:
            find_result = regex.findall(pattern)
            if find_result:
                groups.extend(find_result)
        return groups

    @staticmethod
    def stix_time_to_datetime(s_time):
        """
        Converts datetime to str in "%Y-%m-%dT%H:%M:%S.%fZ" format
        :param s_time: time in string format
        :return: datetime
        """
        try:
            return datetime.strptime(s_time, TAXII_TIME_FORMAT)
        except ValueError:
            return datetime.strptime(s_time, TAXII_TIME_FORMAT_NO_MS)
