from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    params['indicator_type'] = FeedIndicatorType.IP

    params['url'] = 'https://check.torproject.org/exit-addresses'
    params['ignore_regex'] = "^LastStatus|^ExitNode|^Published"
    params['indicator'] = json.dumps({
        "regex": r"^ExitAddress\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s.*",
        "transform": "\\1"
    })

    # Call the main execution of the HTTP API module.
    feed_main('Tor Exit Addresses Feed', params, 'tor-')


from HTTPFeedApiModule import *  # noqa: E402


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
