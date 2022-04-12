import demistomock as demisto
from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    chosen_urls = []
    params['feed_url_to_config'] = {}
    if 'feed_source' in params.keys():
        sources = params['feed_source']
        if 'Last 30 Days' in sources:
            params['feed_url_to_config']['https://urlhaus.abuse.ch/downloads/csv_recent'] = {
                "indicator_type": FeedIndicatorType.URL,
                "ignore_regex": '#*',
                'fieldnames': [
                    'id', 'dateadded', 'url', 'url_status', 'last_online', 'threat', 'tags', 'urlhaus_link', 'reporter'
                ],
                'mapping': {
                    'URLhaus ID': 'id',
                    'Creation Date': 'dateadded',
                    'Value': 'url',
                    'State': 'url_status',
                    'Tags': 'threat',
                    'Tags': 'tags',
                    'Download URL': 'urlhaus_link',
                    'Reported By': 'reporter'
                }
            }
            chosen_urls.append('https://urlhaus.abuse.ch/downloads/csv_recent')

        if 'Currently Active' in sources:
            params['feed_url_to_config']['https://urlhaus.abuse.ch/downloads/csv_online/'] = {
                "indicator_type": FeedIndicatorType.URL,
                "ignore_regex": '#*',
                'fieldnames': [
                    'id', 'dateadded', 'url', 'url_status', 'last_online', 'threat', 'tags', 'urlhaus_link', 'reporter'
                ],
                'mapping': {
                    'URLhaus ID': 'id',
                    'Creation Date': 'dateadded',
                    'Value': 'url',
                    'State': 'url_status',
                    'Tags': 'threat',
                    'Tags': 'tags',
                    'Download URL': 'urlhaus_link',
                    'Reported By': 'reporter'
                }
            }
            chosen_urls.append('https://urlhaus.abuse.ch/downloads/csv_online/')
    params["indicator_type"]: FeedIndicatorType.URL
    params['ignore_regex'] = '#'
    params['url'] = chosen_urls
    feed_main('URLhaus Feed', params, 'urlhaus-feed-')


from CSVFeedApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
