from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    subfeeds = ['all', 'ssh', 'mail', 'apache', 'imap', 'ftp', 'sip', 'bots', 'strongips', 'ircbot', 'bruteforcelogin']

    feed_types = dict()

    for subfeed in subfeeds:
        feed_types[F'https://lists.blocklist.de/lists/{subfeed}.txt'] = {
            'indicator_type': FeedIndicatorType.IP,
        }

    params['feed_url_to_config'] = feed_types

    chosen_subfeeds = list()
    for subfeed in argToList(demisto.params().get('subfeeds', [])):
        chosen_subfeeds.append(F'https://lists.blocklist.de/lists/{subfeed}.txt')

    params['feed_url_to_config'] = feed_types

    chosen_subfeeds = list()
    for subfeed in argToList(demisto.params().get('subfeeds', [])):
        chosen_subfeeds.append(F'https://lists.blocklist.de/lists/{subfeed}.txt')

    params['url'] = chosen_subfeeds

    # Call the main execution of the HTTP API module.
    feed_main('Blocklist_de Feed', params)


from HTTPFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
