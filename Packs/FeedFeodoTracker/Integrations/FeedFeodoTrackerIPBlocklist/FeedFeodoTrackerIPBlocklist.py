from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    chosen_urls = []
    params['feed_url_to_config'] = {}
    sources = params['feed_source']
    if 'Last 30 Days' in sources:
        params['feed_url_to_config']['https://feodotracker.abuse.ch/downloads/ipblocklist.csv'] = {
            "indicator_type": FeedIndicatorType.IP,
            "indicator": {
                "regex": r"^.+,\"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\"?",
                "transform": "\\1"
            },
            "fields": [{
                'firstseenbysource': {
                    "regex": r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})",
                    "transform": "\\1"
                },
                "port": {
                    "regex": r"^.+,.+,(\d{1,5}),",
                    "transform": "\\1"
                },
                "updatedate": {
                    "regex": r"^.+,.+,.+,(\d{4}-\d{2}-\d{2})",
                    "transform": "\\1"
                },
                "malwarefamily": {
                    "regex": r"^.+,.+,.+,.+,(.+)",
                    "transform": "\\1"
                }
            }],
        }
        chosen_urls.append('https://feodotracker.abuse.ch/downloads/ipblocklist.csv')

    if 'Currently Active' in sources:
        params['feed_url_to_config']["https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"] = {
            "indicator_type": FeedIndicatorType.IP,
            "indicator": {
                "regex": r"^\"?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\"?",
                "transform": "\\1"
            },
            "ignore_regex": '#*'
        }
        chosen_urls.append('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt')

    params['ignore_regex'] = '#'
    params['url'] = chosen_urls
    params['custom_fields_mapping'] = {
        "firstseenbysource": "firstseenbysource",
        "port": "port",
        "lastseenbysource": "lastseenbysource",
        "malwarefamily": "malwarefamily"
    }

    # Call the main execution of the HTTP API module.
    feed_main('Feodo Tracker IP Blocklist Feed', params, 'feodotracker-ipblocklist-')


from HTTPFeedApiModule import *  # noqa: E402


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
