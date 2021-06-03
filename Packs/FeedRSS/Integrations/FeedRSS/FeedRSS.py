import email.utils
from time import mktime

import feedparser

from CommonServerPython import *
import html2text


class Client(BaseClient):
    """Client for RSS Feed - gets STIX reports from the website
    Attributes:
        server_url(str): The RSS URL.
        use_ssl: Whether to use ssl.
        proxy(str): Use system proxy.
    """

    def __init__(self, server_url, use_ssl, proxy, feed_tags, tlp_color):
        super().__init__(base_url=server_url, proxy=proxy, verify=use_ssl)
        self.feed_tags = feed_tags
        self.tlp_color = tlp_color
        feed_content = self._http_request(method='GET', resp_type='response')
        self.feed_data = feedparser.parse(feed_content.text)
        self.parsed_indicators = self.create_indicators_from_response()

    def create_indicators_from_response(self) -> list:
        parsed_indicators: list = []

        for indicator in reversed(self.feed_data.entries):
            publications = []
            if indicator:
                published = email.utils.parsedate(indicator.published)
                if published:
                    published_iso = datetime.fromtimestamp(mktime(published)).isoformat()
                    publications.append({
                        'timestamp': indicator.get('published'),
                        'link': indicator.get('link'),
                        'source': self.base_url,
                        'title': indicator.get('title')
                    })
                    text = self.get_url_content(indicator.get('link'))
                    indicator_obj = {
                        "type": 'Report',
                        "value": indicator.get('title'),
                        'Publications': publications,
                        'description': text,
                        "summary": indicator.get('summary'),
                        "rawJSON": {
                            'value': indicator,
                            'type': 'Report',
                            "firstseenbysource": published_iso,
                        },
                        'fields': {'tags': self.feed_tags}
                    }
                    if self.tlp_color:
                        indicator_obj['fields']['trafficlightprotocol'] = self.tlp_color

                parsed_indicators.append(indicator_obj)

        return parsed_indicators


# def fetch_indicators(client: Client) -> list:
    # last_run = demisto.getLastRun()
    # last_fetch = last_run.get('last_fetch')
    #
    # if last_fetch is None:
    #     last_fetch = datetime(1970, 1, 1)
    # else:
    #     last_fetch = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%S.%f')

    # for entry in reversed(client.feed_data.entries):
    #
    #     date_parsed = email.utils.parsedate(entry.published)
    #     if date_parsed:
    #         dt = datetime.fromtimestamp(mktime(date_parsed))
    #
    #         if dt > last_fetch:
    #             incident = {
    #                 'name': entry.title,
    #                 'occurred': dt.isoformat(),
    #                 'rawJSON': json.dumps(entry)
    #             }
    #
    #             indicators.append(incident)
    #
    # dtnow = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')
    # demisto.setLastRun({'last_fetch': dtnow})
    #
    # return client.parsed_indicators


    def get_url_content(self, url):
        h = html2text.HTML2Text()
        f = self._http_request(url)
        return h.handle(f.text)



def get_indicators(client: Client, args: dict) -> CommandResults:
    limit = int(args.get('limit', 10))
    headers = ['value', 'summary', 'link', 'author']
    hr_ = tableToMarkdown(name='RSS Feed:', t=client.parsed_indicators[:limit], headers=headers)
    return CommandResults(
        readable_output=hr_,
        raw_response=client.feed_data
    )


def main():
    params = demisto.params()

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(server_url=params.get('server_url'),
                        use_ssl=not params.get('insecure', False),
                        proxy=params.get('proxy'),
                        feed_tags=argToList(params.get('feedTags')),
                        tlp_color=params.get('tlp_color'))

        if demisto.command() == 'test-module':
            # if the client was created successfully and there is data in feed the test is successful.
            return_results("ok")
        elif demisto.command() == 'rss-get-indicators':
            # return_results(get_indicators(client, demisto.args()))
            client.parsed_indicators[:limit]
            for iter_ in batch(client.parsed_indicators[:10], batch_size=2000):
                demisto.createIndicators(iter_)
        elif demisto.command() == 'fetch-indicators':
            for iter_ in batch(client.parsed_indicators, batch_size=2000):
                demisto.createIndicators(iter_)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')
            # Log exceptions and return errors

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(err)}")


if __name__ in ('builtin__', 'builtins', '__main__'):
    main()