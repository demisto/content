import email.utils
import json
import ssl
from datetime import datetime
from time import mktime

import demistomock as demisto  # noqa: F401
import feedparser
from CommonServerPython import *  # noqa: F401


def fetch_incidents(url):

    feed = feedparser.parse(url)
    incidents = []

    # demisto.getLastRun() will returns an obj with the previous run in it.
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    if last_fetch == None:
        last_fetch = datetime(1970, 1, 1)
    else:
        last_fetch = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%S.%f')

    for entry in feed.entries:

        date_parsed = email.utils.parsedate(entry.published)
        dt = datetime.fromtimestamp(mktime(date_parsed))

        incident = {
            'name': entry.title,
            'occured': dt.isoformat(),
            'rawJSON': json.dumps(entry)
        }

        incidents.append(incident)

    dtnow = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')
    demisto.setLastRun({'last_fetch': dtnow})

    return incidents


##
try:
    if demisto.command() == 'test-fetch-rss':
        print(fetch_incidents(demisto.params().get('URL')))

    elif demisto.command() == 'fetch-incidents':
        demisto.incidents(fetch_incidents(demisto.params().get('URL')))

    elif demisto.command() == 'test-module':
        response = http_request('GET', 'path/file?param=test').json()
        demisto.results("ok")
        sys.exit(0)

except Exception as e:
    LOG(e)
    # LOG.print_log()
    # return_error(e)
