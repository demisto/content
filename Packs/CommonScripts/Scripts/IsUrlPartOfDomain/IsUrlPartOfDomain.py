from typing import List, Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def main(domain_name: str, urls: str) -> CommandResults:
    """Checks that the urls are in the domain in the domain name.

    Args:
        domain_name: A domain
        urls: URLs to check if the domain in them.

    Returns:
        Results to display in CortexXSOAR
    """
    urls = argToList(urls)
    domain = domain_name.lower()

    outputs: List[Dict] = list()
    for url in urls:
        results = demisto.executeCommand('ExtractDomainFromUrlAndEmail', {'input': url.lower()})
        if is_error(results):
            demisto.debug(f'Could not get domain from url {url}')
            return_warning(get_error(results))
        else:
            domain_from_url = results[0]['Contents']
            outputs.append({
                'URL': url,
                'Domain': domain,
                'IsInternal': domain == domain_from_url
            })
    return CommandResults('IsUrlPartOfDomain', 'URL', outputs)


if __name__ in ('builtins', '__builtin__'):
    return_results(main(**demisto.args()))
