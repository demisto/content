import email.utils
from datetime import datetime
from time import mktime

import demistomock as demisto  # noqa: F401
import feedparser
from CommonServerPython import *  # noqa: F401


def fetch_incidents(url):
    feed = feedparser.parse(url)
    incidents = []

    last_run = demisto.getLastRun()
    last_fetch = last_run.get('last_fetch')

    if last_fetch is None:
        last_fetch = datetime(1970, 1, 1)
    else:
        last_fetch = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%S.%f')

    for entry in reversed(feed.entries):
        print("yana")

        date_parsed = email.utils.parsedate(entry.published)
        if date_parsed:
            dt = datetime.fromtimestamp(mktime(date_parsed))

            if dt > last_fetch:
                incident = {
                    'name': entry.title,
                    'occured': dt.isoformat(),
                    'rawJSON': json.dumps(entry)
                }

                incidents.append(incident)

    dtnow = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')
    demisto.setLastRun({'last_fetch': dtnow})

    return incidents


try:
    feedurl = demisto.params().get('URL')

    if demisto.command() == 'fetch-incidents':
        demisto.incidents(fetch_incidents(feedurl))

    elif demisto.command() == 'test-module':
        feed = feedparser.parse(feedurl)
        if 'title' in feed.feed:
            return_results("ok")

except Exception as e:
    return_error(str(e))
