from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    params['indicator_type'] = FeedIndicatorType.IP

    params['url'] = 'http://danger.rulez.sk/projects/bruteforceblocker/blist.php'
    params['ignore_regex'] = "^#.*"
    params['indicator'] = json.dumps({
        "regex": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    })

    fields = json.dumps({
        "lastseenbysource": {
            "regex": r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
            "transform": "\\1"
        }
    })
    params['fields'] = fields

    params['custom_fields_mapping'] = {
        "lastseenbysource": "lastseenbysource"
    }

    # Call the main execution of the HTTP API module.
    feed_main('BruteForceBlocker Feed', params, 'bruteforceblocker-')


from HTTPFeedApiModule import *  # noqa: E402


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
