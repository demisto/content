"""
Script to check if a domain or a sub domain is part of a given domain
"""
from CommonServerPython import *

MAXIMUM_NUMBER_OF_RECORDS = 10


def check_sub_domains_in_domain(domain_name: str, sub_domains_to_check: list) -> CommandResults:
    """

    Args:
        domain_name (str) : main domain
        sub_domains_to_check (list) : list of domains or sub domains that should be checked

    Returns:
        CommandResults included:
        1. outputs (dict of) :
             {
             IsInternalDomain: [{
            - DomainToTest : a subdomain (from the given list of subdomains)
            - DomainToCompare : the main domain
            - IsInternal : True / False if this subdomain is / is not in the given main domain. }]
            }
        2. readable_output (markdown table) : contains first 10 entries with the above headers:
           ["DomainToTest", "DomainToCompare", "IsInternal"]
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

    table = tableToMarkdown("", markdown[:MAXIMUM_NUMBER_OF_RECORDS], headers)
    return CommandResults(outputs={'IsInternalDomain': context_entry}, readable_output=table)


def main():
    args = demisto.args()
    domain_name = args.get('domain_name')
    sub_domains_to_check = argToList(args.get('domain_to_check'))
    if len(sub_domains_to_check) == 0:
        return_error("Error: please specify at least one possible sub domain to check.")
    return_results(check_sub_domains_in_domain(domain_name, sub_domains_to_check))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
