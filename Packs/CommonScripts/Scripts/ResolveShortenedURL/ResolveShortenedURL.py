import re

import demistomock as demisto  # noqa: F401
import urllib2
from CommonServerPython import *  # noqa: F401

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    'Accept-Encoding': 'none',
    'Accept-Language': 'en-US,en;q=0.8',
    'Connection': 'keep-alive'
}

url = demisto.args()['url']

req = urllib2.Request('https://unshorten.me/json/' + url, headers=headers)
page = urllib2.urlopen(req)
content = json.loads(page.read())
if content['success'] == True:
    resolvedUrl = content['resolved_url']
    shortenedUrl = content['requested_url']
    usageCount = content['usage_count']
    ec = {}
    ec['URL.Data'] = [resolvedUrl]
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': [resolvedUrl],
        'ContentsFormat': formats['json'],
        'HumanReadable': tableToMarkdown('Shorten URL results', [{
            'Shortened URL': shortenedUrl,
            'Resolved URL': resolvedUrl,
            'Usage count': usageCount
        }]),
        'EntryContext': ec
    })
else:
    demisto.results('Provided URL could not be un-shortened')
