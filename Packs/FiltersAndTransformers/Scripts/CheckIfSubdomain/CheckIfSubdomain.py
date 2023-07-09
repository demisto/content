import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import tldextract


def main():
    """
    Checks if a given domain (or domains) are subdomains of the specified internal domains.

    Args:
        internal_domains: List of domains defined by the user as internal
        domains: List of domains to check if they are subdomains of the internal ones.

    Returns:
        Bool: True if domain is a subdomain of one of the internal domains
    """

    internal_domains = argToList(demisto.args()['right'])
    domains = argToList(demisto.args()['left'])

    try:

        no_fetch_extract = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None)

        for domain in domains:
            ext = no_fetch_extract(domain)
            top_domain_found = any(ext.registered_domain == internal_domain.replace('*.', '')
                                   for internal_domain in internal_domains)

            demisto.results(top_domain_found)

    except Exception as e:
        return_error(f'Failed to execute CheckIfSubdomain. Error: {str(e)}')


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
