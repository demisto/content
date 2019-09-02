import demistomock as demisto
from CommonServerPython import *
import requests
import os

requests.packages.urllib3.disable_warnings()

if demisto.args().get('use_system_proxy') == 'false':
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']
verify_ssl = demisto.args().get('trust_any_certificate') != 'true'

u = demisto.args()['url']
if not u.lower().startswith('http'):
    u = 'http://' + u
if demisto.args()['useHead'] == 'true':
    response = requests.head(u, allow_redirects=True, verify=verify_ssl)
else:
    requests.get(u, verify=verify_ssl)
urls = []
if response.history:
    for resp in response.history:
        urls.append({'Data': resp.url, 'Status': resp.status_code})
urls.append({'Data': response.url, 'Status': response.status_code})
ec = {'URL(val.Data == obj.Data)': [{'Data': url['Data']} for url in urls]}

demisto.results({'ContentsFormat': formats['json'], 'Type': entryTypes['note'], 'Contents': urls,
                 'ReadableContentsFormat': formats['markdown'],
                 'HumanReadable': tableToMarkdown('URLs', urls, ['Data', 'Status']), 'EntryContext': ec})
