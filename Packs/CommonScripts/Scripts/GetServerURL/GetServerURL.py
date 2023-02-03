import demistomock as demisto
from CommonServerPython import *
from urllib.parse import urlparse, ParseResult


def main():
    urls = demisto.demistoUrls()
    server_url = urls.get('server', '')

    server_url_parts: ParseResult = urlparse(server_url)
    host_name = server_url_parts.hostname
    port = server_url_parts.port
    scheme = server_url_parts.scheme

    server_address = {
        'Scheme': scheme,
        'Host': host_name,
        'Port': port,
        'URL': server_url
    }

    return_outputs(server_url, {'ServerURL': server_address}, server_url)


if __name__ in ('__builtin__', 'builtins'):
    main()
