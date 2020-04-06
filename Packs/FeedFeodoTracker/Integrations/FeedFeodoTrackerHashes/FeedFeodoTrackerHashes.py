from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    params['indicator_type'] = FeedIndicatorType.File
    params['indicator'] = json.dumps({
        "regex": r"^.+,(.+),",
        "transform": "\\1"
    })

    params['fields'] = json.dumps({
        "firstseenbysource": {
            "regex": r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})",
            "transform": "\\1"
        },
        "malwarefamily": {
            "regex": r"^.+,.+,(.+)",
            "transform": "\\1"
        }
    })

    params['ignore_regex'] = '#'

    params['custom_fields_mapping'] = {
        "firstseenbysource": "firstseenbysource",
        "malwarefamily": "malwarefamily"
    }
    params['url'] = "https://feodotracker.abuse.ch/downloads/malware_hashes.csv"
    # Call the main execution of the HTTP API module.
    feed_main('Feodo Tracker Hashes Feed', params, 'feodotracker-hashes-')


from HTTPFeedApiModule import *  # noqa: E402


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
