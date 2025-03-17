import json
import traceback
from typing import Any

import demistomock as demisto
from CommonServerPython import *


def get_entry_context(domains, is_single) -> dict[str, Any]:
    urls_to_return = []
    if is_single:
        if domains.startswith(("http://", "https://")):  # NOSONAR
            urls_to_return.append(domains)
        else:
            urls_to_return.append(f"http://{domains}")  # NOSONAR
            urls_to_return.append(f"https://{domains}")
    else:
        for domain in domains:
            if domain.startswith(("http://", "https://")):  # NOSONAR
                urls_to_return.append(domain)
            else:
                urls_to_return.append(f"http://{domain}")  # NOSONAR
                urls_to_return.append(f"https://{domain}")
    ec = {"DomainToURL": urls_to_return}
    return ec


def main() -> None:
    try:
        domains = demisto.args().get("domains", [])
        if domains[0] == "[" and domains[-1] == "]":
            domains = json.loads(domains)
            ec = get_entry_context(domains, False)
        else:
            ec = get_entry_context(domains, True)
        demisto.results({"Type": entryTypes["note"], "EntryContext": ec, "Contents": {}, "ContentsFormat": formats["json"]})
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Error occurred while extracting Domain(s):\n{e}")


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
