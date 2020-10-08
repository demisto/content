"""
Script to check if a domain or a sub domain is part of a given domain
"""
from CommonServerPython import *

LIMIT_OF_TABLE = 10


def check_sub_domains_in_domain(domain_name: str, sub_domains_to_check: list) -> CommandResults:
    """

    Args:
        domain_name: main domain
        sub_domains_to_check: list of domains or sub domains that should be checked

    Returns:
        for each domain for the list an entry with True / False if it is in the domain or not
    """
    context_entry = []
    markdown = []
    headers = ["DomainToTest", "DomainToCompare", "IsInternal"]
    for sub_domain in sub_domains_to_check:
        is_in_domain = domain_name in sub_domain
        context_entry.append({
            'DomainToTest': sub_domain,
            'DomainToCompare': domain_name,
            'IsInternal': is_in_domain
        })
        markdown.append({"DomainToTest": sub_domain,
                         "DomainToCompare": domain_name,
                         "IsInternal": is_in_domain})

    table = tableToMarkdown("", markdown[:LIMIT_OF_TABLE], headers)
    return CommandResults(outputs={'IsInternalDomain': context_entry}, readable_output=table)


def main():
    args = demisto.args()
    domain_name = args.get('domain_name')
    sub_domains_to_check = argToList(args.get('domain_to_check'))
    if len(sub_domains_to_check) == 0:
        return_error("IsInternalDomainName has to get at least one domainToCheck")
    return_results(check_sub_domains_in_domain(domain_name, sub_domains_to_check))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
