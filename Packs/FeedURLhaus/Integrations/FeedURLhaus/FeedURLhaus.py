from CommonServerPython import *
from CSVFeedApiModule import *


def main():  # pragma: no cover
    try:
        params = {k: v for k, v in demisto.params().items() if v is not None}
        args = demisto.args()
        params = params | args
        base_url = 'https://urlhaus.abuse.ch/downloads/'
        chosen_urls = []
        params['feed_url_to_config'] = {}
        url = urljoin(base_url + 'csv_online')
        params['feed_url_to_config'][url] = {
            "indicator_type": FeedIndicatorType.URL,
            "ignore_regex": '#*',
            'fieldnames': ['id', 'dateadded', 'url', 'url_status', 'last_online', 'threat',
                           'tags', 'urlhaus_link', 'reporter'],
            'mapping': {
                'Creation Date': 'dateadded',
                'Value': 'url',
                'State': 'url_status',
                'Tags': 'tags',
                'Download URL': 'urlhaus_link',
                'Reported By': 'reporter'
            }
        }
        chosen_urls.append(url)
        params["indicator_type"] = FeedIndicatorType.URL
        params['ignore_regex'] = '#'
        params['url'] = chosen_urls
        feed_main('URLhaus Feed', params, 'urlhaus-')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
