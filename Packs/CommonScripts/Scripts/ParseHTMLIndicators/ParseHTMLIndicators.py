import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

import requests
from bs4 import BeautifulSoup
from tld import get_tld


def strip_html_tags(page):
    # Parse the HTML content
    soup = BeautifulSoup(page.content, "html.parser")
    # Strip irrelevant tags
    for data in soup(['style', 'script', 'header', 'head', 'footer', 'aside', 'a']):
        data.decompose()
    return(' '.join(soup.stripped_strings))


def validate_domains(domains, unescape_domain, TLD_exclusion):
    # TLD exclusion and validation for domain indicators
    bad_domain_TLD = set()
    for indicator in domains:
        if unescape_domain and not (get_tld(indicator, fail_silently=True)):
            bad_domain_TLD.add(indicator)
            continue

        for tld in TLD_exclusion:
            if indicator.endswith(tld):
                bad_domain_TLD.add(indicator)
    return(bad_domain_TLD)


def main():
    # Retrieve demisto args
    args = demisto.args()
    blog_url = args.get("url")
    headers = {'user-agent': 'PANW-XSOAR'}
    page = requests.get(blog_url, verify=False, headers=headers)  # nosec
    page.raise_for_status()

    exclusion_list = set(argToList(args.get("exclude_indicators")))
    TLD_exclusion = argToList(args.get("exclude_TLD"))
    unescape_domain = argToBoolean(args.get("unescape_domain"))

    # Allow domain regex replacement between "[.]" and "."
    domain_regex = r"([a-zA-Z0-9]+?\[?\.?\]?[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\[\.\][a-zA-Z]{2,}\[?\.?\]?[a-zA-Z]{0,})"
    if unescape_domain:
        domain_regex = domain_regex.replace("\[\.\]", "\.")

    # Declare indicator regexs
    url_regex = r"([https|ftp|hxxps]+:[//|\\\\]+[\w\d:#@%/;$()~_\+-=\\\[\.\]&]*)"
    ip_regex = r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[" \
               r"0-9])"
    cve_regex = r"(CVE-\d{4}-\d{4,7})"

    page_update = strip_html_tags(page)

    # Extract indicators using regex
    md5 = set(md5Regex.findall(page_update))
    sha1 = set(sha1Regex.findall(page_update))
    sha256 = set(sha256Regex.findall(page_update))
    domain = set(re.findall(domain_regex, page_update))
    url = set(re.findall(url_regex, page_update))
    ip = set(re.findall(ip_regex, page_update))
    cve = set(re.findall(cve_regex, page_update, flags=re.IGNORECASE))

    # Validate the domain indicators
    bad_domain_TLD = validate_domains(domain, unescape_domain, TLD_exclusion)

    # Combine all indicators
    blog_indicators = (md5 | sha1 | sha256 | domain | url | ip | cve) - exclusion_list - bad_domain_TLD

    return_results(CommandResults(readable_output='\n'.join(blog_indicators), outputs={
                   "http.parsedBlog.indicators": list(blog_indicators), "http.parsedBlog.sourceLink": blog_url}))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
