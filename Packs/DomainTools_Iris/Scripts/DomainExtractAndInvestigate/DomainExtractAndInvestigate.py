from CommonServerPython import *


def main():
    url = demisto.args()['url']
    include_context = demisto.args().get('include_context', None)
    res = demisto.executeCommand('ExtractDomainFromUrlAndEmail', {'input': url})

    if not isinstance(res, list) or 'Contents' not in res[0] or not res[0]['Contents']:
        raise ValueError(f'Cannot extract domain from url: {url}')

    domains = [domain['Contents'] for domain in res if 'Contents' in domain]
    parameters = ','.join(domains)

    return_results(
        demisto.executeCommand('domaintoolsiris-investigate', {'domain': parameters, 'include_context': include_context}))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
