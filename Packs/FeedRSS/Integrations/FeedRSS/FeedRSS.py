import feedparser

from CommonServerPython import *
from bs4 import BeautifulSoup

HTML_TAGS = ['p', 'table', 'ul', 'ol', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']

INTEGRATION_NAME = 'RSS Feed'


class Client(BaseClient):
    """Client for RSS Feed - gets Reports from the website
    Attributes:
        server_url(str): The RSS URL.
        use_ssl: Whether to use ssl.
        proxy(str): Use system proxy.
    """

    def __init__(self, server_url, use_ssl, proxy, reliability, feed_tags, tlp_color, content_max_size=45,
                 read_timeout=20):
        super().__init__(base_url=server_url, proxy=proxy, verify=use_ssl)
        self.feed_tags = feed_tags
        self.tlp_color = tlp_color
        self.content_max_size = content_max_size * 1000
        self.parsed_indicators = []
        self.feed_data = None
        self.reliability = reliability
        self.read_timeout = read_timeout

    def request_feed_url(self):
        return self._http_request(method='GET', resp_type='response', timeout=self.read_timeout,
                                  full_url=self._base_url)

    def parse_feed_data(self, feed_response):
        try:
            if feed_response:
                self.feed_data = feedparser.parse(feed_response.text)
        except Exception as err:
            raise DemistoException(f"Failed to parse feed.\nError:\n{str(err)}")

    def create_indicators_from_response(self):
        parsed_indicators: list = []
        if not self.feed_data:
            raise DemistoException(f"Could not parse feed data {self._base_url}")

        for indicator in reversed(self.feed_data.entries):
            publications = []
            if indicator:
                published = dateparser.parse(indicator.published)
                if not published:
                    continue
                published_iso = published.strftime('%Y-%m-%dT%H:%M:%S')
                publications.append({
                    'timestamp': indicator.get('published'),
                    'link': indicator.get('link'),
                    'source': self._base_url,
                    'title': indicator.get('title')
                })
                text = self.get_url_content(indicator.get('link'))
                if not text:
                    continue
                indicator_obj = {
                    "type": 'Report',
                    "value": indicator.get('title').replace(',', ''),  # Remove comma because the script of create
                    # relationship includes that as a list of titles.
                    "rawJSON": {'value': indicator, 'type': 'Report', "firstseenbysource": published_iso},
                    "reliability": self.reliability,
                    "fields": {
                        'rssfeedrawcontent': text,
                        'publications': publications,
                        'description': indicator.get('summary'),
                        'tags': self.feed_tags,
                    }
                }
                if self.tlp_color:
                    indicator_obj['fields']['trafficlightprotocol'] = self.tlp_color

            parsed_indicators.append(indicator_obj)

        return parsed_indicators

    def get_url_content(self, link: str) -> str:
        """Returns the link content only from the relevant tags (listed on HTML_TAGS). For better performance - if the
         extracted content is bigger than "content_max_size" we trim him"""

        response_url = self._http_request(method='GET', full_url=link, resp_type='str', timeout=self.read_timeout)
        report_content = 'This is a dumped content of the article. Use the link under Publications field to read ' \
                         'the full article. \n\n'
        soup = BeautifulSoup(response_url.content, "html.parser")
        for tag in soup.find_all():
            if tag.name in HTML_TAGS:
                for string in tag.stripped_strings:
                    report_content += ' ' + string
        try:
            encoded_content = report_content.encode('utf-8', errors='replace')
        except Exception as err:
            demisto.debug(f"Fail encoding the article content, skipping report {link}. \nError:\n{str(err)}")
            return ""
        if len(encoded_content) > self.content_max_size:  # Ensure report_content does not exceed the
            # indicator size limit (~50KB)
            report_content = encoded_content[:self.content_max_size].decode('utf-8', errors='replace')
            report_content += ' This is truncated text, report content was too big.'

        return report_content


def fetch_indicators(client: Client):
    feed_response = client.request_feed_url()
    client.parse_feed_data(feed_response)
    parsed_indicators = client.create_indicators_from_response()
    return parsed_indicators


def get_indicators(client: Client, indicators: list, args: dict) -> CommandResults:
    limit = int(args.get('limit', 10))
    parsed_indicators = indicators[:limit]
    parsed_for_hr = []
    for indicator in parsed_indicators:
        link = indicator.get('fields', {}).get('publications', [{}])[0].get('link')
        article_title = indicator.get('value', '')
        article_field_hr = article_title
        if link:
            article_field_hr = f"[{article_title}]({link})"  # if there is a link to the article, we want the
            # article's title to be a link.
        parsed_for_hr.append({'Article': article_field_hr,
                              'Type': indicator.get('type')})
    headers = ['Article', 'Type']
    hr_ = tableToMarkdown(name=INTEGRATION_NAME, t=parsed_for_hr, headers=headers)
    return CommandResults(
        readable_output=hr_,
        raw_response=client.feed_data
    )


def check_feed(client: Client) -> str:
    feed_response = client.request_feed_url()
    if feed_response and 'html' in feed_response.headers['content-type']:
        raise DemistoException(f'{feed_response.url} is not rss feed url. Try look for a url containing xml format data,'
                               f' that could be found under urls with \'feed\' prefix or suffix.')
    else:
        client.parse_feed_data(feed_response)  # If parse response will raise an error, test will fail.
        return "ok"


def main():
    params = demisto.params()
    server_url = (params.get('server_url')).rstrip()
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        reliability = params.get('feedReliability')
        reliability = reliability if reliability else DBotScoreReliability.F

        if DBotScoreReliability.is_valid_type(reliability):
            reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        else:
            raise Exception("Please provide a valid value for the Source Reliability parameter.")
        client = Client(server_url=server_url,
                        use_ssl=not params.get('insecure', False),
                        proxy=params.get('proxy'),
                        reliability=reliability,
                        feed_tags=argToList(params.get('feedTags')),
                        tlp_color=params.get('tlp_color'),
                        content_max_size=int(params.get('max_size', '45')),
                        read_timeout=int(params.get('read_timeout', '20')))

        if command == 'test-module':
            return_results(check_feed(client))

        elif command == 'rss-get-indicators':
            parsed_indicators = fetch_indicators(client)
            return_results(get_indicators(client, parsed_indicators, demisto.args()))

        elif command == 'fetch-indicators':
            parsed_indicators = fetch_indicators(client)
            for iter_ in batch(parsed_indicators, batch_size=2000):
                demisto.createIndicators(iter_)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as err:
        return_error(f"Failed to execute {INTEGRATION_NAME} with {command} command.\nError:\n{str(err)}")


if __name__ in ('builtin__', 'builtins', '__main__'):
    main()
