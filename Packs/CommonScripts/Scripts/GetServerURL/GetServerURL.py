from urllib.parse import ParseResult, urlparse

import demistomock as demisto
from CommonServerPython import *


def main():
    urls = demisto.demistoUrls()
    server_url = urls.get("server", "")

    server_url_parts: ParseResult = urlparse(server_url)
    host_name = server_url_parts.hostname
    port = server_url_parts.port
    scheme = server_url_parts.scheme

    server_address = {"Scheme": scheme, "Host": host_name, "Port": port, "URL": server_url}
    return_results(
        CommandResults(
            readable_output=server_url,
            outputs=server_address,
            raw_response=server_url,
            outputs_prefix="ServerURL",
            outputs_key_field="URL",
        )
    )


if __name__ in ("__builtin__", "builtins"):
    main()
