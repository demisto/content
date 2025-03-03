from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    services = ['all', 'ssh', 'mail', 'apache', 'imap', 'ftp', 'sip', 'bots', 'strongips', 'bruteforcelogin']

    feed_types = {}

    for service in services:
        feed_types[F'https://lists.blocklist.de/lists/{service}.txt'] = {
            'indicator_type': FeedIndicatorType.IP,
        }

    params['feed_url_to_config'] = feed_types

    # Automatically infer the indicator type
    params['auto_detect_type'] = True

    chosen_services = []
    for service in argToList(demisto.params().get('services', [])):
        chosen_services.append(F'https://lists.blocklist.de/lists/{service}.txt')

    params['url'] = chosen_services

    # Call the main execution of the HTTP API module.
    feed_main('Blocklist_de Feed', params, 'blocklist_de-')


from HTTPFeedApiModule import *  # noqa: E402

if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
