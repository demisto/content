import demistomock as demisto
from CommonServerPython import *

import json
import traceback
from typing import Any, Dict


def get_entry_context(domains, isSingle) -> Dict[str, Any]:
    urls_to_return = []
    if isSingle:
        if domains.startswith('http://') or domains.startswith('https://'):
            urls_to_return.append(domains)
        else:
            urls_to_return.append("http://{}".format(domains))
            urls_to_return.append("https://{}".format(domains))
    else:
        for domain in domains:
            if domain.startswith('http://') or domain.startswith('https://'):
                urls_to_return.append(domain)
                continue
            else:
                urls_to_return.append("http://{}".format(domain))
                urls_to_return.append("https://{}".format(domain))
    ec = {"DomainToURL": urls_to_return}
    return ec


def main() -> None:
    try:
        domains = demisto.args().get('domains', [])
        if domains[0] == '[' and domains[-1] == ']':
            domains = json.loads(domains)
            ec = get_entry_context(domains, False)
        else:
            ec = get_entry_context(domains, True)
        demisto.results(
            {"Type": entryTypes['note'], "EntryContext": ec, "Contents": {}, "ContentsFormat": formats["json"]})
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error occurred while extracting Domain(s):\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
