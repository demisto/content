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
    results = demisto.executeCommand('ExtractDomainFromUrlAndEmail', {'input': domain_name})
    domain = results[0]['Contents']

    if not domain:
        return_error(f'Could not find a domain in "{domain_name}"')
    domain = domain.lower()

    outputs: list = list()
    for url in urls:
        results = demisto.executeCommand('ExtractDomainFromUrlAndEmail', {'input': url.lower()})
        domain_from_url = results[0]['Contents']
        outputs.append({
            'URL': url,
            'Domain': domain,
            'IsInternal': domain == domain_from_url
        })
    return CommandResults('IsUrlPartOfDomain', 'Data', outputs)


if __name__ in ('builtins', '__builtin__'):
    return_results(main(**demisto.args()))
