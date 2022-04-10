import tldextract

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


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

    for domain in domains:
        for internal_domain in internal_domains:
            ext = tldextract.extract(domain)
            if ext.registered_domain == internal_domain.replace('*.', ''):
                demisto.results(True)
                return

        demisto.results(False)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
