import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def url_to_uuid(url: str):
    uuid = url.split('/')[-1]
    return uuid


def main():
    uuids = []
    input_urls = demisto.args().get('input')
    input_urls = argToList(input_urls)
    for url in input_urls:
        uuids.append(url_to_uuid(url))
    demisto.results(uuids)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
