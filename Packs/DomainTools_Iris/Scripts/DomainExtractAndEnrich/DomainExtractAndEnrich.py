from CommonServerPython import *


def main():
    url = demisto.args().get('url', None)
    include_context = demisto.args().get('include_context', None)
    res = demisto.executeCommand('ExtractDomainFromUrlAndEmail', {'input': url})

    if not isinstance(res, list) or 'Contents' not in res[0] or not res[0]['Contents']:
        raise ValueError('Cannot extract domain from url: {}'.format(url.encode('utf-8')))

    domains = [domain['Contents'] for domain in res if 'Contents' in domain]
    parameters = ','.join(domains)
    return_results(demisto.executeCommand('domaintoolsiris-enrich', {'domain': parameters, 'include_context': include_context}))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
