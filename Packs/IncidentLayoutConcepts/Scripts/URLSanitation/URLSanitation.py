import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Script is designed to de-duplicate, decode, un-escape, whitelist and drop (images, logos and other non-clickables) URLs

import json
import re
from urllib.parse import urlparse, unquote, urljoin, quote

ec = {}
finalList = []

# Create list from the input
WHITELISTED = 0
FIXED = 0
DECODED = 0
CLEANED = 0
UNSHORTNED = 0
PURGED = 0

# Validate and drop invalid URLs


def url_validator(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.path])
    except:
        demisto.log('bad url: ' + str(url))
        return False

# Fix unescaped URLs


def url_fixer(url):
    try:
        par = urlparse(url)
    except:
        demisto.log('bad url: ' + str(url))
        return False
    # Test results of the urlparse function
    if not bool(par.netloc) and not bool(par.scheme):
        # Try unparsing first
        if url_validator(urlparse(url, scheme='http').geturl()):
            return urlparse(url, scheme='http').geturl()
    elif not bool(par.scheme):
        # Try unparsing firstg
        if url_validator(urlparse(url, scheme='http').geturl()):
            return urlparse(url, scheme='http').geturl()
    elif not bool(par.path) and not bool(par.scheme):
        # Try parse and add a '/' to the end
        turl = urlparse(turl, scheme='http').geturl()
        turl = urljoin(url, '/')
        if url_validator(turl):
            return turl
    elif not bool(par.path):
        # Try adding a '/' to the end
        if url_validator(urljoin(url, '/')):
            return urljoin(url, '/')
    elif url_validator(unquote(url)):
        # Try unquoting the URL
        return unquote(url)
    elif url_validator(quote(url)):
        # Try quoting the URL
        return quote(url)
    else:
        # Try manual fixes
        if re.match(r'/\[\.\]/g', url):
            url = re.sub(r'/\[\.\]/g', '.', url)
        if re.match(r'/hxxp/i', url):
            url = re.sub(r'/hxxp/i', 'http', url)
        if re.match(r'/hxxp/i', url):
            url = re.sub(r'/&amp;/g', '&', url)
        if url_validator(url):
            return url
        else:
            demisto.log('Unfixable URL: ' + url)
            return False


# New Start
tempURL = demisto.args()['url']
if not type(tempURL) == list:
    demisto.results("Invalid list")
    exit(0)
domain = demisto.args().get('domain')
purgeImageURLs = demisto.args()['purgeImageURLs']

for url in tempURL:
    if not url_validator(url):
        res = url_fixer(url)
        # URL is invalid, attempt to fix it
        if bool(res):
            FIXED += 1
            url = res
        else:
            demisto.info("%s - Unable to fix invalid URL - %s" % (demisto.incidents()[0]['investigationId'], str(url)))
            PURGED += 1
            continue
    # Check if the URL is whitelisted
    checkWhitelist = demisto.executeCommand("isWhitelisted", {"value": url})[0]['EntryContext']['iswhitelisted']
    if checkWhitelist:
        demisto.info("%s - URL whitelisted - %s" % (str(demisto.incidents()[0]['investigationId']), str(url)))
        WHITELISTED += 1
        continue

    # Check of the URL contains any PII information
    if domain:
        reg = re.findall(r'[a-zA-Z\.]+@' + str(domain) + r'\.com', url)
        if reg:
            CLEANED += 1
            url = url.replace(reg[0], 'username@domain.com')
    """
    # Decode SafeLinks URL
    if 'safelinks.protection' in url:
        temp = demisto.executeCommand('get_url_from_safelink_url_v2', { 'text': url })[0]['Contents']['Chemours_URL']
        if temp != url:
            DECODED += 1
            url = temp
    # Try to unshorten the URL
    result = demisto.executeCommand('ResolveShortenedURL', { 'url' : url })[0]['Contents']
    if type(result) == list:
        if str(result[0]) != url:
            UNSHORTNED += 1
            url = result[0]
    """
    # Revalidate URL
    if not url_validator(url):
        # URL is invalid, attempt to fix it
        if bool(url_fixer(url)):
            url = url_fixer(url)
        else:
            demisto.info("%s - Unable to fix invalid URL after other functions - %s" %
                         (demisto.incidents()[0]['investigationId'], str(url)))
            PURGED += 1
            continue

    # Remove URLs that point to image files
    if purgeImageURLs == "true":
        if str(url).endswith('.png') or str(url).endswith('.jpg') or str(url).endswith('.tiff') or str(url).endswith('.bmp') or str(url).endswith('.gif') or str(url).endswith('.jpeg'):
            PURGED += 1
            continue

    # Check if URL already exists
    if url not in finalList:
        finalList.append(url)

demisto.results("WHITELISTED = %d FIXED = %d DECODED = %d CLEANED = %d UNSHORTNED = %d PURGED = %d" %
                (WHITELISTED, FIXED, DECODED, CLEANED, UNSHORTNED, PURGED))

ec = {'URLSanitationList': finalList}
output = ''
for item in finalList:
    output = output + ' - ' + str(item) + '\n'

demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['json'],
    'Contents': ec,
    'EntryContext': ec,
    'ReadableContentsFormat': formats['markdown'],
    'HumanReadable': output})
