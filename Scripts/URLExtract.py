import re

strURLRegex = r'(?i)(?:(?:https?|ftp):\/\/|www\.|ftp\.)(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#\/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[A-Z0-9+&@#\/%=~_|$])'

res = []
urls = []
filtered = ['http://schemas.microsoft.com/office/2004/12/omml', 'http://www.w3.org/TR/REC-html40']

data = demisto.args()['text']

for m in re.finditer(strURLRegex, data, re.I):
    u = m.group(0)
    if u in filtered:
        continue
    if u in urls:
        continue
    if 'mailto:' in u:
        continue
    urls.append(u)

res.append('URLs found:\n' + '\n'.join(urls))
currUrls = demisto.get(demisto.context(), 'urls')
if currUrls and isinstance(currUrls, list):
    for u in urls:
        if u not in currUrls:
            currUrls.append(u)
else:
    currUrls = urls
demisto.setContext('urls', currUrls)
demisto.results(res)
