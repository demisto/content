from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}
    chosen_urls = []
    params['feed_url_to_config'] = {}
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
        "malwarefamily": "malwarefamily",
        "relationship_entity_b": "relationship_entity_b"
    }

    # Call the main execution of the HTTP API module.
    feed_main('Feodo Tracker IP Blocklist Feed', params, 'feodotracker-ipblocklist-')


from HTTPFeedApiModule import *  # noqa: E402


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
