import demistomock as demisto
from CommonServerPython import *
from CSVFeedApiModule import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    sources_enum = {'Last 30 Days': 'csv_recent', 'Currently Active': 'csv_online'}
    base_url = 'https://urlhaus.abuse.ch/downloads/'
    chosen_urls = []
    params['feed_url_to_config'] = {}
    if 'feed_source' in params.keys():
        sources = params['feed_source']
        for source in sources:
            if source not in sources_enum:
                continue
            suffix = sources_enum[source]
            params['feed_url_to_config'][base_url + suffix] = {
                "indicator_type": FeedIndicatorType.URL,
                "ignore_regex": '#*',
                'fieldnames': ['id', 'dateadded', 'url', 'url_status', 'last_online', 'threat',
                               'tags', 'urlhaus_link', 'reporter'],
                'mapping': {
                    'URLhaus ID': 'id',
                    'Creation Date': 'dateadded',
                    'Value': 'url',
                    'State': 'url_status',
                    'Tags': 'tags',
                    'Download URL': 'urlhaus_link',
                    'Reported By': 'reporter'
                }
            }
            chosen_urls.append(base_url + suffix)
    params["indicator_type"] = FeedIndicatorType.URL
    params['ignore_regex'] = '#'
    params['url'] = chosen_urls
    feed_main('URLhaus Feed', params, 'urlhaus-feed-')



if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
