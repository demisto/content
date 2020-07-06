import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def main(args: dict) -> CommandResults:
    domain_name = args.get('domain_name')
    urls = argToList(args.get('urls'))
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
            'Data': url,
            'IsInternal': domain == domain_from_url
        })
    return CommandResults('IsUrlPartOfDomain', 'Data', outputs)


if __name__ in ('builtins', '__builtin__'):
    return_results(main(demisto.args()))
