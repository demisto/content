import re

strURLRegex = r'(?i)(?:(?:https?|ftp):\/\/|www\.|ftp\.)(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#\/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[A-Z0-9+&@#\/%=~_|$])'

res = []
urls = []
badUrls = []
filtered = ['http://schemas.microsoft.com/office/2004/12/omml', 'http://www.w3.org/TR/REC-html40']

data = demisto.args()['data'] if demisto.get(demisto.args(), 'data') else demisto.incidents()[0]['details']

if isinstance(data, list):
    urls = data[:]
else:
    for m in re.finditer(strURLRegex, data, re.I):
        u = m.group(0)
        if u in filtered:
            continue
        if u in urls:
            continue
        if 'mailto:' in u:
            continue
        urls.append(u)

for u in urls:
    rep = demisto.executeCommand('url', {'url': u})
    for r in rep:
        if positiveUrl(r):
            badUrls.append(u)
            res.append(shortUrl(r))

if len(res) > 0:
    res.extend(['yes', 'Found malicious URLs!'])
    currUrls = demisto.get(demisto.context(), 'bad_urls')
    if currUrls and isinstance(currUrls, list):
        currUrls += [u for u in badUrls if u not in currUrls]
    else:
        currUrls = badUrls
    demisto.setContext('bad_urls', currUrls)
else:
    res.append('no')
    res.append('Only clean URLs found: \n' + '\n'.join(urls))

demisto.results(res)
