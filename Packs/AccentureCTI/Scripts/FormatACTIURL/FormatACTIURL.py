import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def url_to_uuid(url: str):
    uuid = url.split('/')[-1]
    return uuid


def main():
    uuids = []  # pragma: no cover
    input_urls = demisto.args().get('input')  # pragma: no cover
    input_urls = argToList(input_urls)  # pragma: no cover
    for url in input_urls:  # pragma: no cover
        uuids.append(url_to_uuid(url))  # pragma: no cover
    demisto.results(uuids)  # pragma: no cover


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
