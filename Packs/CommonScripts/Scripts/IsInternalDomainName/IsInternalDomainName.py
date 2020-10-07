"""
Script to check if a domain or a sub domain is part of a given domain
"""
from CommonServerPython import *


def check_in_domain(domain_name: str, domain_to_check: list) -> CommandResults:
    """

    Args:
        domain_name: main domain
        domain_to_check: list of domains or sub domains that should be checked

    Returns:
        for each domain for the list an entry with True / False if it is in the domain or not
    """
    context_entry = []
    for element in domain_to_check:
        is_in_domain = False
        # split by domain name
        domain_to_check_prefix = element.split(domain_name)[0]
        if domain_to_check_prefix + domain_name == element:
            is_in_domain = True
        context_entry.append({
            'Domain.Name': element,
            'Domain.IsInternal': True if is_in_domain else False
        })
    return CommandResults(outputs=context_entry)


def get_domains_from_context(context_path: str):
    """

    Args:
        context_path: context path to look for list of sub domains

    Returns: list of sub domains

    """
    context_path_list = context_path.split(".")
    domain_to_check: List = []
    for key in context_path_list:
        if key not in demisto.context():
            # in case got a key which does not exist in context
            domain_to_check = []
            break
        domain_to_check = demisto.context()[key]
    return domain_to_check


def main():
    args = demisto.args()
    domain_name = args.get('domainName')
    domain_to_check = argToList(args.get('domainToCheck'))
    if len(domain_to_check) == 0:
        context_path = args.get('contextPath')
        if not context_path:
            return_error("IsInternalDomainName has to get one of the following : contextPath or domainToCheck")
        domain_to_check = get_domains_from_context(context_path)
        if len(domain_to_check) == 0:
            return_error("IsInternalDomainName has to get one of the following : contextPath or domainToCheck")
    return_results(check_in_domain(domain_name, domain_to_check))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
