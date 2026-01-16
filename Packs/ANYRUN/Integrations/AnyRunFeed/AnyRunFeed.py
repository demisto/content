from datetime import datetime

import demistomock as demisto
from CommonServerPython import *

from anyrun.connectors import FeedsConnector
from anyrun.iterators import FeedsIterator
from anyrun import RunTimeException

DATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
VERSION = "PA-XSOAR:2.1.0"


def test_module(params: dict) -> str:  # pragma: no cover
    """Performs ANY.RUN API call to verify integration is operational"""
    try:
        with FeedsConnector(
            params.get("credentials", {}).get("password"), integration=VERSION, verify_ssl=not params.get("insecure")
        ) as connector:
            connector.check_authorization()
            return "ok"
    except RunTimeException as exception:
        return str(exception)


def extract_indicator_data(indicator: dict) -> tuple[str, str]:
    """
    Extracts indicator type, value using raw indicator

    :param indicator: Raw ANY.RUN indicator
    :return: ANY.RUN indicator type, ANY.RUN indicator value
    """
    pattern = indicator.get("pattern", "")
    indicator_type = pattern.split(":")[0][1:]
    indicator_value = pattern.split(" = '")[1][:-2]

    return indicator_type, indicator_value


def get_timestamp(params: dict) -> str:  # pragma: no cover
    """
    Extracts actual fetch timestamp

    :param params: Demisto params
    :return: Fetch timestamp
    """
    if demisto.getLastRun():
        return demisto.getLastRun().get("next_fetch")
    return params.get("modified_after", "")


def update_timestamp(new_timestamp: datetime | None) -> None:  # pragma: no cover
    """
    Updates fetch timestamp if exists

    :param new_timestamp: New generated fetch timestamp
    """
    if new_timestamp:
        if demisto.getLastRun():
            actual_timestamp = datetime.strptime(demisto.getLastRun().get("next_fetch"), DATE_TIME_FORMAT)

            if new_timestamp > actual_timestamp:
                demisto.setLastRun({"next_fetch": new_timestamp.strftime(DATE_TIME_FORMAT)})
        else:
            demisto.setLastRun({"next_fetch": new_timestamp.strftime(DATE_TIME_FORMAT)})


def convert_indicators(indicators: list[dict]) -> list[dict]:
    """
    Converts ANY.RUN indicator to XSOAR indicator format

    :param indicators: ANY.RUN indicator
    :return: XSOAR indicator
    """
    converted_indicators: list[dict] = []

    for indicator in indicators:
        indicator_type, indicator_value = extract_indicator_data(indicator)

        indicator_payload = {
            "value": indicator_value,
            "type": {"ipv4-addr": "IP", "url": "URL", "domain-name": "Domain"}.get(indicator_type),
            "fields": {
                "firstseenbysource": indicator.get("created"),
                "first_seen": indicator.get("created"),
                "modified": indicator.get("modified"),
                "last_seen": indicator.get("modified"),
                "vendor": "ANY.RUN",
                "source": "ANY.RUN TI Feed",
            },
        }

        converted_indicators.append(indicator_payload)

    return converted_indicators


def fetch_indicators_command(params: dict) -> None:  # pragma: no cover
    """
    Initializes the update of indicators

    :param params: Demisto params
    """
    modified_after = get_timestamp(params)

    with FeedsConnector(
        params.get("credentials", {}).get("password"), integration=VERSION, verify_ssl=not params.get("insecure")
    ) as connector:
        connector._taxii_delta_timestamp = None
        for chunk in FeedsIterator.taxii_stix(
            connector, match_type="indicator", match_version="all", modified_after=modified_after, limit=10000, chunk_size=10000
        ):
            demisto.createIndicators(convert_indicators(chunk))

        update_timestamp(connector._taxii_delta_timestamp)


def main():  # pragma: no cover
    """Main Execution block"""
    params = demisto.params()

    if params.get("proxy"):
        handle_proxy()

    try:
        if demisto.command() == "fetch-indicators":
            fetch_indicators_command(params)
        elif demisto.command() == "test-module":
            result = test_module(params)
            return_results(result)
        else:
            raise NotImplementedError(f"Command {demisto.command()} is not implemented")
    except RunTimeException as exception:
        return_error(exception.description, error=str(exception.json))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
