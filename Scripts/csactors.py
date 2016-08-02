import time

def formatDate(t):
    if t:
        return time.ctime(t)
    return ''

def formatSlugs(slugs):
    res = ''
    first = True
    if slugs:
        for s in slugs:
            if first:
                first = False
            else:
                res += ', '
            res += demisto.gets(s, 'value')
    return res

res = '## CrowdStrike Falcon Intelligence'
entry = demisto.executeCommand('cs-actors', demisto.args())[0]
if entry['Type'] != entryTypes['error'] and entry['ContentsFormat'] == formats['json']:
    meta = demisto.get(entry, 'Contents.meta')
    if meta:
        res += '\n\n### Metadata'
        res += '\n|Total|Offset|Limit|Time|'
        res += '\n|-----|------|-----|----|'
        res += '\n| ' + demisto.gets(meta, 'paging.total') + ' | ' + demisto.gets(meta, 'paging.offset') + ' | ' + demisto.gets(meta, 'paging.limit') + ' | ' + demisto.gets(meta, 'query_time') + ' |'
    resources = demisto.get(entry, 'Contents.resources')
    if resources:
        res += '\n\n### Actors'
        res += '\n|ID|Name|Short Description|URL|Known As|Create Date|First Date|Last Date|Origins|Target Countries|Target Industries|Motivations|'
        res += '\n|--|----|-----------------|---|--------|-----------|----------|---------|-------|----------------|-----------------|-----------|'
        for r in resources:
            res += '\n| ' + demisto.gets(r, 'id') + ' | ' + demisto.gets(r, 'name') + ' | ' + demisto.gets(r, 'short_description') + ' | ' + demisto.gets(r, 'url') + ' | ' + \
                   demisto.gets(r, 'known_as') + ' | ' + formatDate(demisto.get(r, 'created_date')) + ' | ' +  formatDate(demisto.get(r, 'first_activity_date')) + ' | ' + \
                   formatDate(demisto.get(r, 'last_activity_date')) + ' | ' + formatSlugs(demisto.get(r, 'origins')) + ' | ' + formatSlugs(demisto.get(r, 'target_countries')) + ' | ' + \
                   formatSlugs(demisto.get(r, 'target_industries')) + ' | ' + formatSlugs(demisto.get(r, 'motivations')) + ' |'
    demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': res})
else:
    demisto.results(entry)