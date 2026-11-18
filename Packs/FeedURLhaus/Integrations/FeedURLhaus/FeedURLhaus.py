from CommonServerPython import *
from CSVFeedApiModule import *

BASE_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/"
EXPORT_FILE_NAME = "online.csv"
MIN_FETCH_INTERVAL_MINUTES = 5
FETCH_INTERVAL_VALIDATED_COMMANDS = ("test-module", "fetch-indicators")
SUPPORTED_COMMANDS = (*FETCH_INTERVAL_VALIDATED_COMMANDS, "urlhaus-get-indicators")


def build_feed_url(auth_key: str) -> str:
    """Builds the v2 export URL. abuse.ch expects the Auth-Key as a path segment."""
    return f"{BASE_URL}{auth_key}/{EXPORT_FILE_NAME}"


def validate_fetch_interval(fetch_interval: Any) -> None:
    """Rejects a Feed Fetch Interval below the abuse.ch minimum (the dump is regenerated every 5 minutes).

    Raises:
        DemistoException: If the interval is lower than the minimum.
    """
    interval = arg_to_number(fetch_interval)
    if interval is not None and interval < MIN_FETCH_INTERVAL_MINUTES:
        raise DemistoException(
            f"The Feed Fetch Interval must be at least {MIN_FETCH_INTERVAL_MINUTES} minutes, as requested by abuse.ch. "
            f"Set it to {MIN_FETCH_INTERVAL_MINUTES} minutes or more in the instance configuration."
        )


def build_feed_params(params: dict, args: dict, auth_key: str) -> dict:
    """Builds the CSVFeedApiModule params for the URLhaus v2 export."""
    feed_params = {k: v for k, v in params.items() if v is not None} | args
    # The Auth-Key is sent in the URL path, so no auth header or basic auth is sent.
    feed_params.pop("credentials", None)
    url = build_feed_url(auth_key)
    feed_params["feed_url_to_config"] = {
        url: {
            "indicator_type": FeedIndicatorType.URL,
            "ignore_regex": "#*",
            "fieldnames": ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"],
            "mapping": {
                "Creation Date": "dateadded",
                "Value": "url",
                "State": "url_status",
                "Tags": "tags",
                "Download URL": "urlhaus_link",
                "Reported By": "reporter",
            },
        }
    }
    feed_params["indicator_type"] = FeedIndicatorType.URL
    feed_params["ignore_regex"] = "#"
    feed_params["url"] = [url]
    return feed_params


def main():  # pragma: no cover
    try:
        command = demisto.command()
        if command not in SUPPORTED_COMMANDS:
            raise NotImplementedError(f"Command {command} is not implemented.")

        params = demisto.params()
        auth_key = params.get("credentials", {}).get("password")
        if not auth_key:
            raise ValueError("Missing required parameter Auth Key. Please set this parameter in the instance configuration.")
        # The Auth-Key is part of the request URL, so mask it in any log or error message.
        add_sensitive_log_strs(auth_key)

        if command in FETCH_INTERVAL_VALIDATED_COMMANDS:
            validate_fetch_interval(params.get("feedFetchInterval"))

        feed_main("URLhaus Feed", build_feed_params(params, demisto.args(), auth_key), "urlhaus-")
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {e!s}")


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
