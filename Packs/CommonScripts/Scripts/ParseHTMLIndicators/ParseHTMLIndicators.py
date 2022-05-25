import re

import demistomock as demisto  # noqa: F401
import requests
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa: F401
from tld import get_tld


def strip_HTML_tags(page):
    # Parse the HTML content
    soup = BeautifulSoup(page.content, "html.parser")
    # Strip irrelevant tags
    for data in soup(['style', 'script', 'header', 'head', 'footer', 'aside', 'a']):
        data.decompose()
    return(' '.join(soup.stripped_strings))


def validate_domains(domains, unescapeDomain, TLDExclusion):
    # TLD exclusion and validation for domain indicators
    badDomainTLD = set()
    for indicator in domains:
        if unescapeDomain == "True" and not (get_tld(indicator, fail_silently=True)):
            badDomainTLD.add(indicator)
            continue

        for tld in TLDExclusion:
            if indicator.endswith(tld):
                badDomainTLD.add(indicator)
    return(badDomainTLD)


def main():
    # Retrieve demisto args
    args = demisto.args()
    blog_url = args.get("url")
    try:
        headers = {'user-agent': 'PANW-XSOAR'}
        page = requests.get(blog_url, verify=False, headers=headers)
        page.raise_for_status
    except requests.HTTPError:
        raise

    exclusionList = set(argToList(args.get("exclude_indicators")))
    TLDExclusion = argToList(args.get("exclude_TLD"))
    unescapeDomain = args.get("unescape_domain")

    # Allow domain regex replacement between "[.]" and "."
    if unescapeDomain == "False":
        domain_regex = r"([a-zA-Z0-9]+?\[?\.?\]?[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\[\.\][a-zA-Z]{2,}\[?\.?\]?[a-zA-Z]{0,})"
    else:
        domain_regex = r"([a-zA-Z0-9]+?\[?\.?\]?[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\[\.\][a-zA-Z]{2,}\[?\.?\]?[a-zA-Z]{0,})"
        domain_regex = domain_regex.replace("\[\.\]", "\.")

    # Declare indicator regexs
    url_regex = r"([https|ftp|hxxps]+:[//|\\\\]+[\w\d:#@%/;$()~_\+-=\\\[\.\]&]*)"
    ip_regex = r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
    cve_regex = r"(CVE-\d{4}-\d{4,7})"

    page_update = strip_HTML_tags(page)

    # Extract indicators using regex
    md5 = set(md5Regex.findall(page_update))
    sha1 = set(sha1Regex.findall(page_update))
    sha256 = set(sha256Regex.findall(page_update))
    domain = set(re.findall(domain_regex, page_update))
    url = set(re.findall(url_regex, page_update))
    ip = set(re.findall(ip_regex, page_update))
    cve = set(re.findall(cve_regex, page_update, flags=re.IGNORECASE))

    # Validate the domain indicators
    badDomainTLD = validate_domains(domain, unescapeDomain, TLDExclusion)

    # Combine all indicators
    blogIndicators = (md5 | sha1 | sha256 | domain | url | ip | cve) - exclusionList - badDomainTLD

    return_results(CommandResults(readable_output='\n'.join(blogIndicators), outputs={
                   "http.parsedBlog.indicators": list(blogIndicators), "http.parsedBlog.sourceLink": blog_url}))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
