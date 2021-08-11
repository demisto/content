import email.utils
from datetime import datetime
from time import mktime

import feedparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    """Client for RSS Feed - gets Reports from the website
    Attributes:
        server_url(str): The RSS URL.
        use_ssl: Whether to use ssl.
        proxy(str): Use system proxy.
    """

    def __init__(self, server_url, use_ssl, proxy):
        super().__init__(base_url=server_url, proxy=proxy, verify=use_ssl)

    def request_feed_url(self):
        return self._http_request(method='GET', resp_type='response')


def parse_feed_data(feed_response):
    try:
        if feed_response:
            return feedparser.parse(feed_response.text)
    except Exception as err:
        raise DemistoException(f"Failed to parse feed.\nError:\n{str(err)}")


def collect_entries_data_from_response(parsed_feed_data):
    entries_data: List[Dict[str, Any]] = []
    if not parsed_feed_data:
        raise DemistoException(f"Could not parse feed data {self._base_url}")

    for entry in reversed(parsed_feed_data.entries):
        if entry:
            published = email.utils.parsedate(entry.published)
            if not published:
                continue

            published_dt = datetime.fromtimestamp(mktime(published))
            published_formatted = published_dt.strftime('%B %-d, %Y %-I:%M %p')

            entries_data.append(
                {
                    'timestamp': published_formatted,
                    'link': entry.get('link'),
                    'title': entry.get('title'),
                    'summary': entry.get('summary')
                }
            )

    return entries_data


def create_widget_content(entries_data: List[Dict[str, Any]]):
    content: str = ''

    for entry_data in entries_data:
        content += f'<h3><a href={entry_data["link"]}>{entry_data["title"]}</a></h3>\n'
        content += f'<i>{entry_data["timestamp"]}</i>\n'
        content += f'<h5>{entry_data["summary"]}</h5>\n'
        content += '<hr>\n'

    content += ''
    return content


def main():
    args = demisto.args()

    client = Client(
        server_url=args['url'],
        use_ssl=not args.get('insecure', False),
        proxy=args.get('proxy', False),
    )

    rss_raw_data = client.request_feed_url()
    parsed_feed_data = parse_feed_data(rss_raw_data)
    entries_data = collect_entries_data_from_response(parsed_feed_data)
    content = create_widget_content(entries_data)

    demisto.results({
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.HTML,
        'Contents': content,
    })


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
