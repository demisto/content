import demistomock as demisto
from CommonServerPython import *

import requests
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Server, Collection

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

BASE_URL = 'https://cti-taxii.mitre.org'


def get_roots(server):
    api_root = server.api_roots[0]
    return api_root


def get_collections(api_root):
    collections = [x for x in api_root.collections]  # type: ignore[attr-defined]
    return collections


def get_server(base_url):
    server_url = urljoin(base_url, '/taxii/')
    server = Server(server_url, verify=False)
    return server


def is_valid_attack_pattern(item):
    """Retrieves all entries from the feed.

    Returns:
        A list of objects, containing the indicators.
    """

    try:
        server = get_server(BASE_URL)
        api_root = get_roots(server)
        collections = get_collections(api_root)
        for collection in collections:
            collection_id = f"stix/collections/{collection.id}/"
            collection_url = urljoin(BASE_URL, collection_id)
            collection_data = Collection(collection_url, verify=False)

            tc_source = TAXIICollectionSource(collection_data)
            attack_pattern_name = tc_source.query([
                Filter("external_references.external_id", "=", item),
                Filter("type", "=", "attack-pattern")
            ])[0]['name']
            if attack_pattern_name:
                return attack_pattern_name

        return False
    except Exception:
        return False


def main():
    attack_list = argToList(demisto.args().get('input'))

    list_results = [is_valid_attack_pattern(attack) for attack in attack_list if is_valid_attack_pattern(attack)]

    if list_results:
        demisto.results(list_results)
    else:
        demisto.results('')


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins" or __name__ == "__main__":
    main()
