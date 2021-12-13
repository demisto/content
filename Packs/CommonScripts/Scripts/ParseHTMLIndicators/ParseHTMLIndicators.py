import re

import demistomock as demisto  # noqa: F401
import requests
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa: F401
from tld import get_tld

# Retrieve demisto args
args = demisto.args()
blog_url = args.get("url")
page = requests.get(blog_url)
exclusionList = argToList(args.get("exclude_indicators"))
TLDExclusion = argToList(args.get("exclude_TLD"))
unescapeDomain = args.get("unescape_domain")
badDomainTLD = []

# parse html content
soup = BeautifulSoup(page.content, "html.parser")
for data in soup(['style', 'script', 'header', 'head', 'footer', 'aside', 'a']):
    # Remove tags
    data.decompose()

page_update = ' '.join(soup.stripped_strings)

# Declare indicators regex
domain_regex = r"([a-zA-Z0-9]+?\.?[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\[\.\][a-zA-Z]{2,}\.?[a-zA-Z]{0,})"
url_regex = r"([https|ftp|hxxps]+:[//|\\\\]+[\w\d:#@%/;$()~_\+-=\\\[\.\]&]*)"
ip_regex = r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
cve_regex = r"(CVE-\d{4}-\d{4,7})"

# Allow domain regex replacement between "[.]" and "."
if unescapeDomain == "True":
    domain_regex = domain_regex.replace("\[\.\]", "\.")

# Extract indicators using regex
md5 = md5Regex.findall(page_update)
sha1 = sha1Regex.findall(page_update)
sha256 = sha256Regex.findall(page_update)
domain = re.findall(domain_regex, page_update)
url = re.findall(url_regex, page_update)
ip = re.findall(ip_regex, page_update)
cve = re.findall(cve_regex, page_update, flags=re.IGNORECASE)

# Indicators exclusion
for ex_indicator in exclusionList:
    domain[:] = (value for value in domain if value != ex_indicator)
    url[:] = (value for value in url if value != ex_indicator)
    ip[:] = (value for value in ip if value != ex_indicator)
    md5[:] = (value for value in md5 if value != ex_indicator)
    sha1[:] = (value for value in sha1 if value != ex_indicator)
    sha256[:] = (value for value in sha256 if value != ex_indicator)
    cve[:] = (value for value in cve if value != ex_indicator)

# Convert domain indicators to url (match Domain Indicator Type formatting script)
domain = ["hxxp://" + sub for sub in domain]

# TLD exclusion for domain indicators
for indicator in domain:
    for ex_tld in TLDExclusion:
        if indicator.endswith(ex_tld):
            badDomainTLD.append(indicator)

# TLD validation for domain regex
if unescapeDomain == "True":
    for dn in domain:
        tldCheck = get_tld(dn, fail_silently=True)
        if not tldCheck:
            badDomainTLD.append(dn)

# Combine all indicators
blogIndicators = [*md5, *sha1, *sha256, *domain, *url, *ip, *cve]

# Remove bad formatted indicators
for fp_indicator in badDomainTLD:
    blogIndicators[:] = (value for value in blogIndicators if value != fp_indicator)

# Keep unique values
blogIndicators = list(dict.fromkeys(blogIndicators))
blogIndicators = str(blogIndicators)

return_results(CommandResults(readable_output=blogIndicators, outputs={
               "http.parsedBlog.indicators": blogIndicators, "http.parsedBlog.sourceLink": blog_url}))
