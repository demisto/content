import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import List, Dict, Set
import json
import requests
from stix2 import TAXIICollectionSource, Filter
from taxii2client import Server, Collection, ApiRoot

''' CONSTANT VARIABLES '''
CONTEXT_PREFIX = 'TAXII2'

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class FeedClient:

    def __init__(self, url, proxies, verify):
        self.base_url = url
        self.proxies = proxies
        self.verify = verify
        self.server: Server
        self.api_root: List[ApiRoot]
        self.collections: List[Collection]

    def get_server(self):
        server_url = urljoin(self.base_url, '/taxii/')
        self.server = Server(server_url, verify=self.verify, proxies=self.proxies)

    def get_roots(self):
        self.api_root = self.server.api_roots[0]

    def get_collections(self):
        self.collections = [x for x in self.api_root.collections]  # type: ignore[attr-defined]

    def initialise(self):
        self.get_server()
        self.get_roots()
        self.get_collections()

    def build_iterator(self, limit: int = -1) -> List:

        """Retrieves all entries from the feed.

        Returns:
            A list of objects, containing the indicators.
        """
        return []


def test_module(client):
    if client.collections:
        demisto.results('ok')
    else:
        return_error('Could not connect to server')


def fetch_indicators(client):
    indicators = client.build_iterator()
    return indicators


def get_indicators_command(client, raw="false", limit=10):
    limit = int(limit)
    raw = raw == "true"

    indicators = client.build_iterator(limit=limit)

    if raw:
        demisto.results({
            "indicators": [x.get('rawJSON') for x in indicators]
        })
        return

    md = f"Found {len(indicators)} results:\n" + tableToMarkdown('', indicators, ['value', 'score', 'type'])
    return CommandResults(outputs_prefix=CONTEXT_PREFIX, outputs_key_field="value", outputs=indicators, readable_output=md)


def get_collections_command(client: FeedClient):
    """
    Get the available collections in the TAXII server
    :param client: FeedClient
    :return: available collections
    """
    collections = list()
    for collection in client.collections:
        collections.append({"Name": collection.title, "ID": collection.id})
    md = tableToMarkdown('TAXII 2 Collections:', collections, ['Name', 'ID'])
    return CommandResults(outputs_prefix=CONTEXT_PREFIX, outputs_key_field="ID", outputs=collections, readable_output=md)


def main():
    params = demisto.params()
    args = demisto.args()
    url = params.get('server')
    proxies = handle_proxy()
    verify_certificate = not params.get('insecure', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = FeedClient(url, proxies, verify_certificate)
        client.initialise()
        commands = {
            'taxii2-get-indicators': get_indicators_command,
            'taxii2-get-collections': get_collections_command,
        }

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_module(client)

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators(client)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            return_results(commands[command](client, *args))

    # Log exceptions
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
