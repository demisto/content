import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *


def main(domains: str, urls: str) -> CommandResults:
    """Checks that the urls are in the domain in the domain name.

    Args:
        domains: A comma separated list of domains.
        urls: A comma separated list of urls.

    Returns:
        Results to display in CortexXSOAR
    """
    urls = argToList(urls)
    domains = set(argToList(domains))

    outputs: list[dict] = list()
    for url in urls:
        results = demisto.executeCommand('ExtractDomainFromUrlAndEmail', {'input': url.lower()})
        if is_error(results):
            demisto.debug(f'Could not get domain from url {url}')
            return_error(get_error(results))
        else:
            domain_from_url = results[0]['Contents']
            outputs.append({
                'URL': url,
                'Domain': domain_from_url,
                'IsInternal': (domain_from_url in domains) or url.startswith(('https://localhost', 'http://localhost'))
            })
    return CommandResults('IsUrlPartOfDomain', outputs=outputs)


if __name__ in ('builtins', '__builtin__'):
    return_results(main(**demisto.args()))
