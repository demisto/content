import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

import types
import re
from taxii2client.exceptions import TAXIIServiceException
from taxii2client import v20, v21

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

""" CONSTANT VARIABLES """
CONTEXT_PREFIX = "TAXII2"
TAXII_VER_2_0 = '2.0'
TAXII_VER_2_1 = '2.1'
DFLT_LIMIT_PER_FETCH = 1000
INDICATOR_VAL_PATTERN = r"(?<=value = ')(.*)(?=')"  # TODO: improve to deal with no / multiple spaces

TAXII_TYPES_TO_DEMISTO_TYPES = {
    'ipv4-addr': FeedIndicatorType.IP,
    'ipv6-addr': FeedIndicatorType.IPv6,
    'domain': FeedIndicatorType.Domain,
    'domain-name': FeedIndicatorType.Domain,
    'url': FeedIndicatorType.URL,
    'md5': FeedIndicatorType.File,
    'sha-1': FeedIndicatorType.File,
    'sha-256': FeedIndicatorType.File,
    'file:hashes': FeedIndicatorType.File,
}


class FeedClient:
    def __init__(self, url, collection_to_fetch, proxies, verify, username=None, password=None):
        self.collection_to_fetch = collection_to_fetch
        self.base_url = url
        self.proxies = proxies
        self.verify = verify
        self.username = username
        self.password = password
        self.server = None
        self.api_root = None
        self.collections = None

    def init_server(self, version=TAXII_VER_2_0):
        server_url = urljoin(self.base_url)
        if version is TAXII_VER_2_0:
            self.server = v20.Server(server_url, verify=self.verify, user=self.username, password=self.password, proxies=self.proxies)
        else:
            self.server = v21.Server(server_url, verify=self.verify, user=self.username, password=self.password, proxies=self.proxies)

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

    def init_collection_to_fetch(self):
        if self.collections and self.collection_to_fetch:
            try:
                for collection in self.collections:
                    if collection.id == self.collection_to_fetch:
                        self.collection_to_fetch = collection
                        break
            except StopIteration:
                raise DemistoException(
                    "Could not find the provided Collection ID in the available collections. "
                    "Please make sure you entered the ID correctly."
                )

    def initialise(self):
        self.init_server()
        self.init_roots()
        self.init_collections()
        self.init_collection_to_fetch()

    def build_iterator(self, limit: int = -1, added_after=None) -> list:
        if not isinstance(self.collection_to_fetch, (v20.Collection, v21.Collection)):
            self.init_collection_to_fetch()

        page_size = self.get_page_size(limit, limit)
        envelope = self.poll_collection(page_size, added_after)
        indicators = self.extract_indicatros_from_envelope(envelope, limit)
        return indicators

    def extract_indicatros_from_envelope(self, envelope, limit):
        indicators = []
        # TAXII 2.0
        if isinstance(envelope, types.GeneratorType):
            obj_cnt = 0
            for sub_envelope in envelope:
                indicators.extend(self.parse_taxii_objects(sub_envelope.get('objects')))
                obj_cnt += 1
                if obj_cnt > limit:
                    break
        # TAXII 2.1
        else:
            cur_limit = limit
            indicators = self.parse_taxii_objects(envelope.get('objects'))
            while envelope.get("more", False) and cur_limit > 0:
                page_size = self.get_page_size(limit, cur_limit)
                envelope = self.poll_collection(page_size, envelope.get("next", ""))
                cur_limit -= len(envelope)
                indicators.extend(self.parse_taxii_objects(envelope.get('objects')))
        return indicators[:limit]

    def poll_collection(self, page_size, added_after):
        get_objects = self.collection_to_fetch.get_objects
        if isinstance(self.collection_to_fetch, v20.Collection):
            envelope = v20.as_pages(get_objects, per_request=page_size, added_after=added_after)
        else:
            envelope = get_objects(limit=page_size, added_after=added_after)
        return envelope

    @staticmethod
    def get_page_size(max_limit, cur_limit):
        return min(DFLT_LIMIT_PER_FETCH, cur_limit) if max_limit > -1 else DFLT_LIMIT_PER_FETCH

    @staticmethod
    def parse_taxii_objects(objects):
        indicators_objects = [item for item in objects if
                              item.get('type') == 'indicator']  # retrieve only indicators

        indicators = []
        if indicators_objects:
            for indicator_object in indicators_objects:
                pattern = indicator_object.get('pattern')
                for key in TAXII_TYPES_TO_DEMISTO_TYPES.keys():
                    if pattern.startswith(f'[{key}'):  # retrieve only Demisto indicator types
                        value = re.search(INDICATOR_VAL_PATTERN, pattern)
                        if value:
                            indicators.append({
                                "value": value,
                                "type": TAXII_TYPES_TO_DEMISTO_TYPES[key],
                                "rawJSON": indicator_object,
                            })

        return indicators


def test_module(client):
    if client.collections:
        demisto.results("ok")
    else:
        return_error("Could not connect to server")


def fetch_indicators_command(client):
    # todo: add treatment to last fetch and first fetch here
    iterator = client.build_iterator(date_to_timestamp(datetime.now()))
    indicators = []
    for item in iterator:
        indicator = item.get("indicator")
        if indicator:
            item["value"] = indicator
            indicators.append(
                {"value": indicator, "type": item.get("type"), "rawJSON": item,}
            )
    return indicators


def get_indicators_command(client, raw="false", limit=10):
    limit = int(limit)
    raw = raw == "true"

    indicators = client.build_iterator(limit=limit)

    if raw:
        demisto.results({"indicators": [x.get("rawJSON") for x in indicators]})
        return

    md = f"Found {len(indicators)} results:\n" + tableToMarkdown(
        "", indicators, ["value", "score", "type"]
    )
    return CommandResults(
        outputs_prefix=CONTEXT_PREFIX,
        outputs_key_field="value",
        outputs=indicators,
        readable_output=md,
    )


def get_collections_command(client: FeedClient):
    """
    Get the available collections in the TAXII server
    :param client: FeedClient
    :return: available collections
    """
    collections = list()
    for collection in client.collections:
        collections.append({"Name": collection.title, "ID": collection.id})
    md = tableToMarkdown("TAXII 2 Collections:", collections, ["Name", "ID"])
    return CommandResults(
        outputs_prefix=CONTEXT_PREFIX,
        outputs_key_field="ID",
        outputs=collections,
        readable_output=md,
    )


def main():
    params = demisto.params()
    args = demisto.args()
    url = params.get("url")
    collection_to_fetch = params.get("collection_to_fetch")
    credentials = params.get('credentials') or {}
    username = credentials.get('identifier')
    password = credentials.get('password')
    proxies = handle_proxy()
    verify_certificate = not params.get("insecure", False)

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    try:
        client = FeedClient(url, collection_to_fetch, proxies, verify_certificate, username, password)
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
            return_results(commands[command](client, *args))

    # Log exceptions
    except Exception as e:
        raise e


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
