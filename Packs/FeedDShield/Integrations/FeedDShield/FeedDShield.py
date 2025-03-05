from CommonServerPython import *


def main():
    params = {k: v for k, v in demisto.params().items() if v is not None}

    params["indicator_type"] = FeedIndicatorType.CIDR

    params["url"] = "https://www.dshield.org/block.txt"
    params["ignore_regex"] = "[#S].*"
    params["indicator"] = json.dumps(
        {"regex": r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t[\d.]*\t(\d{1,2})", "transform": "\\1/\\2"}
    )

    fields = json.dumps(
        {
            "numberofattacks": {"regex": "^.*\\t.*\\t[0-9]+\\t([0-9]+)", "transform": "\\1"},
            "networkname": {"regex": "^.*\\t.*\\t[0-9]+\\t[0-9]+\\t([^\\t]+)", "transform": "\\1"},
            "geocountry": {"regex": "^.*\\t.*\\t[0-9]+\\t[0-9]+\\t[^\\t]+\\t([A-Z]+)", "transform": "\\1"},
            "registrarabuseemail": {"regex": "^.*\\t.*\\t[0-9]+\\t[0-9]+\\t[^\\t]+\\t[A-Z]+\\t(\\S+)", "transform": "\\1"},
        }
    )
    params["fields"] = fields

    params["custom_fields_mapping"] = {"geocountry": "geocountry", "registrarabuseemail": "registrarabuseemail"}

    # Call the main execution of the HTTP API module.
    feed_main("Dshield Feed", params, "dshield-")


from HTTPFeedApiModule import *  # noqa: E402


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
