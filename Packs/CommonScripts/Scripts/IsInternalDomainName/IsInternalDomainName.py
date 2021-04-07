"""
Script to check if a domain or a sub domain is part of a given domain
"""
from CommonServerPython import *

MAXIMUM_NUMBER_OF_RECORDS = 10


def check_sub_domains_in_domain(domains_to_compare: list, sub_domains_to_check: list):
    """

    Args:
        domains_to_compare (list) : list of main domains that should be compared with sub domains
        sub_domains_to_check (list) : list of domains or sub domains that should be checked

    Returns:
        CommandResults included:
        1. outputs (dict of) :
             {
             IsInternalDomain: [{
            - DomainToTest : a subdomain (from the given list of subdomains)
            - DomainToCompare : list of given main domains
            - IsInternal : True / False if this subdomain is / is not in at least one of the given main domains. }]
            }
        2. readable_output (markdown table) : contains first 10 entries with the above headers:
           ["DomainToTest", "DomainToCompare", "IsInternal"]
    """
    context_entry = []
    markdown = []
    headers = ["DomainToTest", "DomainToCompare", "IsInternal"]
    for sub_domain in sub_domains_to_check:
        # in case sub domain is in at least one of the given main domains
        is_in_domain = any(main_domain in sub_domain for main_domain in domains_to_compare)
        context_entry.append({
            'DomainToTest': sub_domain,
            'DomainToCompare': domains_to_compare,
            'IsInternal': is_in_domain
        })
        markdown.append({"DomainToTest": sub_domain,
                         "DomainToCompare": domains_to_compare,
                         "IsInternal": is_in_domain})

    table = tableToMarkdown("", markdown[:MAXIMUM_NUMBER_OF_RECORDS], headers)
    return CommandResults(outputs={'IsInternalDomain': context_entry}, readable_output=table)


def validate_args(domains_to_compare, sub_domains_to_check):
    if len(domains_to_compare) == 0:
        return_error("Error: please specify at least one possible main domain to compare with.")
    elif len(sub_domains_to_check) == 0:
        return_error("Error: please specify at least one possible sub domain to check.")


def main():
    args = demisto.args()
    domains_to_compare = argToList(args.get('main_domains'))
    sub_domains_to_check = argToList(args.get('possible_sub_domains_to_test'))
    validate_args(domains_to_compare, sub_domains_to_check)
    return_results(check_sub_domains_in_domain(domains_to_compare, sub_domains_to_check))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
