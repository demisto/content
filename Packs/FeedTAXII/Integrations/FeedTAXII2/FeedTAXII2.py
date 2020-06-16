import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import Any
import types
import re
from taxii2client.exceptions import TAXIIServiceException
from taxii2client.common import TokenAuth
from taxii2client import v20, v21

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

""" CONSTANT VARIABLES """
CONTEXT_PREFIX = "TAXII2"
INTEGRATION_CONTEXT_TIME_KEY = "last_run"

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
    "ipv6-addr": FeedIndicatorType.IPv6CIDR
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
        self.collection_to_fetch = collection_to_fetch
        self.base_url = url
        self.proxies = proxies
        self.verify = verify
        self.auth = None
        if username and password:
            self.auth = requests.auth.HTTPBasicAuth(username, password)
        elif username:
            self.auth = TokenAuth(key=username)
        self.field_map = field_map if field_map else {}
        self.server = None
        self.api_root = None
        self.collections = None
        self.indicator_regexes = [
            re.compile(INDICATOR_EQUALS_VAL_PATTERN),
            re.compile(HASHES_EQUALS_VAL_PATTERN),
        ]
        self.cidr_regexes = [
            re.compile(CIDR_ISSUBSET_VAL_PATTERN),
            re.compile(CIDR_ISUPPERSET_VAL_PATTERN),
        ]

    def init_server(self, version=TAXII_VER_2_0):
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
        try:
            # try TAXII 2.0
            self.api_root = self.server.api_roots[0]
        except TAXIIServiceException:
            # switch to TAXII 2.1
            self.init_server(version=TAXII_VER_2_1)
            self.api_root = self.server.api_roots[0]

    def init_collections(self):
        self.collections = [x for x in self.api_root.collections]  # type: ignore[attr-defined]

    def init_collection_to_fetch(self, collection_to_fetch=None):
        if collection_to_fetch is None:
            collection_to_fetch = self.collection_to_fetch
        if self.collections and collection_to_fetch:
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
        self, limit: int = -1, added_after=None, collection_to_fetch=None
    ) -> list:
        if not isinstance(self.collection_to_fetch, (v20.Collection, v21.Collection)):
            self.init_collection_to_fetch(collection_to_fetch)
        if not isinstance(self.collection_to_fetch, (v20.Collection, v21.Collection)):
            raise DemistoException(
                "Could not find a collection to fetch from. "
                "Please make sure you provided a collection."
            )

        page_size = self.get_page_size(limit, limit)
        if page_size <= 0:
            return []
        envelope = self.poll_collection(page_size, added_after)
        indicators = self.extract_indicatros_from_envelope(envelope, limit)
        return indicators

    def extract_indicatros_from_envelope(self, envelope, limit):
        indicators = []
        obj_cnt = 0
        # TAXII 2.0
        if isinstance(envelope, types.GeneratorType):
            for sub_envelope in envelope:
                taxii_objects = sub_envelope.get("objects")
                # no fetched objects
                if not taxii_objects:
                    break
                obj_cnt += len(taxii_objects)
                indicators.extend(
                    self.extract_and_parse_taxii_indicators(taxii_objects)
                )
                if len(indicators) >= limit:
                    break
        # TAXII 2.1
        else:
            cur_limit = limit
            taxii_objects = envelope.get("objects")
            obj_cnt += len(taxii_objects)
            indicators = self.extract_and_parse_taxii_indicators(
                envelope.get("objects")
            )
            while envelope.get("more", False) and cur_limit > 0:
                page_size = self.get_page_size(limit, cur_limit)
                envelope = self.poll_collection(page_size, envelope.get("next", ""))
                taxii_objects = envelope.get("objects")
                obj_cnt += len(taxii_objects)
                cur_limit -= len(envelope)
                indicators.extend(
                    self.extract_and_parse_taxii_indicators(taxii_objects)
                )
        demisto.debug(
            f"TAXII 2 Feed has extracted {len(indicators)} indicators / {obj_cnt} taxii objects"
        )
        return indicators[:limit]

    def poll_collection(self, page_size, added_after):
        get_objects = self.collection_to_fetch.get_objects
        if isinstance(self.collection_to_fetch, v20.Collection):
            envelope = v20.as_pages(
                get_objects, per_request=page_size, added_after=added_after
            )
        else:
            envelope = get_objects(limit=page_size, added_after=added_after)
        return envelope

    @staticmethod
    def get_page_size(max_limit, cur_limit):
        return (
            min(DFLT_LIMIT_PER_FETCH, cur_limit)
            if max_limit > -1
            else DFLT_LIMIT_PER_FETCH
        )

    def extract_and_parse_taxii_indicators(self, taxii_objs):
        field_map = self.field_map if self.field_map else {}
        indicators_objs = [
            item for item in taxii_objs if item.get("type") == "indicator"
        ]  # retrieve only indicators

        indicators = []
        if indicators_objs:
            for indicator_obj in indicators_objs:
                indicators.extend(self.parse_indicator(indicator_obj, field_map))
        return indicators

    def parse_indicator(self, indicator_obj, field_map):
        pattern = indicator_obj.get("pattern")
        indicators = []
        if pattern:
            # this is done in case the server doesn't properly space the operator,
            # supported indicators have no spaces, so this action shouldn't affect extracted values
            trimmed_pattern = pattern.replace(" ", "")

            cidr_groups = self.extract_indicator_groups_from_pattern(
                trimmed_pattern, self.cidr_regexes
            )
            indicator_groups = self.extract_indicator_groups_from_pattern(
                trimmed_pattern, self.indicator_regexes
            )

            if indicator_groups:
                indicators.extend(
                    self.get_indicators_from_indicator_groups(
                        indicator_groups,
                        indicator_obj,
                        TAXII_TYPES_TO_CORTEX_TYPES,
                        field_map))
            if cidr_groups:
                indicators.extend(
                    self.get_indicators_from_indicator_groups(
                        cidr_groups, indicator_obj, TAXII_TYPES_TO_CORTEX_CIDR_TYPES, field_map))
        return indicators

    def get_indicators_from_indicator_groups(
        self, indicator_groups, indicator_obj, indicator_types, field_map
    ):
        indicators = []
        for term in indicator_groups:
            for taxii_type in indicator_types.keys():
                """
                term should be list with 2 argument parsed with regex
                [`type`, `indicator`]
                """
                if len(term) == 2 and taxii_type in term[0]:
                    type_ = indicator_types[taxii_type]
                    value = term[1]
                    indicator = self.create_indicator(
                        indicator_obj, type_, value, field_map
                    )
                    indicators.append(indicator)
                    break
        return indicators

    def extract_indicator_groups_from_pattern(self, pattern, regexes):
        groups = []
        for regex in regexes:
            find_result = regex.findall(pattern)
            if find_result:
                groups.extend(find_result)
        return groups

    def create_indicator(self, indicator_obj, type_, value, field_map):
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

    def extract_indicator_values(self, pattern, type_):
        if type_ == FeedIndicatorType.File:
            # todo: add file treatment here
            pass
        return re.search(INDICATOR_EQUALS_VAL_PATTERN, pattern.replace(" ", ""))


def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


def test_module(client):
    if client.collections:
        demisto.results("ok")
    else:
        return_error("Could not connect to server")


def fetch_indicators_command(client):
    iterator = client.build_iterator()
    indicators = []
    for item in iterator:
        indicator = item.get("indicator")
        if indicator:
            item["value"] = indicator
            indicators.append(
                {"value": indicator, "type": item.get("type"), "rawJSON": item,}
            )
    return indicators


def get_indicators_command(client, raw="false", limit=10, added_after=None):
    limit = try_parse_integer(limit, "Please provide a valid limit (positive integer)")
    if added_after:
        added_after, _ = parse_date_range(added_after, date_format=TAXII_TIME_FORMAT)
    raw = raw == "true"

    indicators = client.build_iterator(limit=limit, added_after=added_after)

    if raw:
        demisto.results({"indicators": [x.get("rawJSON") for x in indicators]})
        return

    md = f"Found {len(indicators)} results:\n" + tableToMarkdown(
        "", indicators, ["value", "type"]
    )
    if indicators:
        return CommandResults(
            outputs_prefix=CONTEXT_PREFIX,
            outputs_key_field="value",
            outputs=indicators,
            readable_output=md,
        )
    return md


def get_collections_command(client: Taxii2FeedClient):
    """
    Get the available collections in the TAXII server
    :param client: FeedClient
    :return: available collections
    """
    collections = list()
    for collection in client.collections:
        collections.append({"Name": collection.title, "ID": collection.id})
    md = tableToMarkdown("TAXII2 Server Collections:", collections, ["Name", "ID"])
    return CommandResults(
        outputs_prefix=CONTEXT_PREFIX + ".Collections",
        outputs_key_field="ID",
        outputs=collections,
        readable_output=md,
    )


def main():
    params = demisto.params()
    args = demisto.args()
    url = params.get("url")
    collection_to_fetch = params.get("collection_to_fetch")
    credentials = params.get("credentials") or {}
    username = credentials.get("identifier")
    password = credentials.get("password")
    proxies = handle_proxy()
    verify_certificate = not params.get("insecure", False)

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    try:
        client = Taxii2FeedClient(
            url, collection_to_fetch, proxies, verify_certificate, username, password
        )
        client.initialise()
        commands = {
            "taxii2-get-indicators": get_indicators_command,
            "taxii2-get-collections": get_collections_command,
        }

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            test_module(client)

        elif demisto.command() == "fetch-indicators":
            indicators = fetch_indicators_command(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)
        else:
            return_results(commands[command](client, **args))

    # Log exceptions
    except Exception as e:
        return_error(
            f"Failed to execute {command} command. Error: {str(e)}\n\ntraceback: {traceback.format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
