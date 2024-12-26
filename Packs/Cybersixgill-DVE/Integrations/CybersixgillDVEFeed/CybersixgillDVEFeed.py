import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """
from typing import Any
from collections.abc import Callable
from collections import OrderedDict
import traceback
import requests

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_feed_client import SixgillFeedClient
from sixgill.sixgill_constants import FeedStream
from sixgill.sixgill_utils import is_indicator


""" CONSTANTS """
INTEGRATION_NAME = "Sixgil_DVE_Feed"
CHANNEL_CODE = "7698e8287dfde53dcd13082be750a85a"
MAX_INDICATORS = 100
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SUSPICIOUS_FEED_IDS = ["darkfeed_003"]
DEMISTO_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
VERIFY = not demisto.params().get("insecure", True)
SESSION = requests.Session()
DESCRIPTION_FIELD_ORDER = OrderedDict(
    [
        ("Description", "eventdescription"),
        ("Created", "creationdate"),
        ("Modified", "modified"),
        ("External id", "externalid"),
        ("Sixgill DVE score - current", "sixgilldvescorecurrent"),
        ("Sixgill DVE score - highest ever date", "sixgilldvescorehighesteverdate"),
        ("Sixgill DVE score - highest ever", "sixgilldvescorehighestever"),
        ("Sixgill - Previously exploited probability", "sixgillpreviouslyexploitedprobability"),
        ("Event Name", "eventname"),
        ("Event Type", "eventtype"),
        ("Event Action", "eventaction"),
        ("Previous level", "previouslevel"),
        ("Event Description", "eventdescription"),
        ("Event Datetime", "eventdatetime"),
        ("CVSS 3.1 score", "cvss31score"),
        ("CVSS 3.1 severity", "cvss31severity"),
        ("NVD Link", "nvdlink"),
        ("NVD - last modified date", "nvdlastmodifieddate"),
        ("NVD - publication date", "nvdpublicationdate"),
        ("CVSS 2.0 score", "cvss20score"),
        ("CVSS 2.0 severity", "cvss20severity"),
        ("NVD Vector - V2.0", "nvdvectorv20"),
        ("NVD Vector - V3.1", "nvdvectorv31"),
    ]
)


""" HELPER FUNCTIONS """


def module_command_test(*args):
    """
    Performs basic Auth request
    """
    response = SESSION.send(
        request=SixgillAuthRequest(
            demisto.params()["client_id"], demisto.params()["client_secret"], CHANNEL_CODE
        ).prepare(),
        verify=VERIFY,
    )
    if not response.ok:
        raise DemistoException("Auth request failed - please verify client_id, and client_secret.")
    return "ok", None, "ok"


def get_description(fileds_obj):
    description_string = ""
    for name, sixgill_name in DESCRIPTION_FIELD_ORDER.items():
        description_string += f"{name}: {fileds_obj.get(sixgill_name)}\n"
    fileds_obj["description"] = description_string
    return fileds_obj


def create_fields(stix_obj, event_obj, nvd_obj, score_obj, ext_id):
    fields = {}
    try:
        fields = {
            "description": "",
            "creationdate": stix_obj.get("created", ""),
            "modified": stix_obj.get("modified", ""),
            "externalid": ext_id,
            "sixgilldvescorecurrent": score_obj.get("current", ""),
            "sixgilldvescorehighesteverdate": score_obj.get("highest", {}).get("date", ""),
            "sixgilldvescorehighestever": score_obj.get("highest", {}).get("value", ""),
            "sixgillpreviouslyexploitedprobability": score_obj.get("previouslyExploited", ""),
            "eventname": event_obj.get("name", ""),
            "eventtype": event_obj.get("type", ""),
            "eventaction": event_obj.get("action", ""),
            "previouslevel": event_obj.get("prev_level", ""),
            "eventdescription": event_obj.get("description", ""),
            "eventdatetime": event_obj.get("event_datetime", ""),
            "cvss31score": nvd_obj.get("base_score_v3", ""),
            "cvss31severity": nvd_obj.get("base_severity_v3", ""),
            "nvdlink": nvd_obj.get("link", ""),
            "nvdlastmodifieddate": nvd_obj.get("modified", ""),
            "nvdpublicationdate": nvd_obj.get("published", ""),
            "cvss20score": nvd_obj.get("score_2_0", ""),
            "cvss20severity": nvd_obj.get("severity_2_0", ""),
            "nvdvectorv20": nvd_obj.get("vector_v2", ""),
            "nvdvectorv31": nvd_obj.get("vector_v3", ""),
        }
    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{err}]\nTrace:\n{traceback.format_exc()}'
        raise DemistoException(err_msg)
    return fields


def stix_to_indicator(stix_obj, tags: list = [], tlp_color: str | None = None):
    indicator: dict[str, Any] = {}
    try:
        ext_obj = stix_obj.get("external_references", [])
        ext_id = ""
        if ext_obj and ext_obj[0]:
            ext_id = ext_obj[0].get("external_id")
        event_obj = stix_obj.get("x_sixgill_info", {}).get("event", {})
        nvd_obj = stix_obj.get("x_sixgill_info", {}).get("nvd", {})
        score_obj = stix_obj.get("x_sixgill_info", {}).get("score", {})
        fields = create_fields(stix_obj, event_obj, nvd_obj, score_obj, ext_id)
        fields = get_description(fields)
        indicator["value"] = ext_id
        indicator["type"] = "CVE"
        indicator["rawJSON"] = {"value": ext_id, "type": "CVE"}
        indicator["rawJSON"].update(stix_obj)
        indicator["score"] = 3
        indicator["fields"] = fields
        if tlp_color:
            indicator["fields"]["trafficlightprotocol"] = str(tlp_color)
        if tags:
            indicator["fields"]["tags"] = tags
    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{err}]\nTrace:\n{traceback.format_exc()}'
        raise DemistoException(err_msg)
    return indicator


def fetch_indicators_command(
    client, limit: int = 0, get_indicators_mode: bool = False, tags: list = [], tlp_color: str | None = None
):
    indicators_list = []
    try:
        records = client.get_bundle()
        records = records.get("objects", [])
        for rec in records:
            if is_indicator(rec):
                ind = stix_to_indicator(rec, tags, tlp_color)
                indicators_list.append(ind)
            if get_indicators_mode and len(indicators_list) == limit:
                break
        if not get_indicators_mode:
            client.commit_indicators()
    except Exception as err:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{err}]\nTrace:\n{traceback.format_exc()}'
        raise DemistoException(err_msg)
    return indicators_list


def get_indicators_command(client, args):
    limit = int(args.get("limit"))
    final_indicators = fetch_indicators_command(client, limit, True)
    human_readable = tableToMarkdown("Indicators from Sixgill DVE Feed:", final_indicators)
    return human_readable, {}, final_indicators


def get_limit(str_limit, default_limit):
    try:
        return int(str_limit)
    except Exception:
        return default_limit


def main():
    max_indicators = get_limit(demisto.params().get("maxIndicators", MAX_INDICATORS), MAX_INDICATORS)
    SESSION.proxies = handle_proxy()
    client = SixgillFeedClient(
        demisto.params()["client_id"],
        demisto.params()["client_secret"],
        CHANNEL_CODE,
        FeedStream.DVEFEED,
        bulk_size=max_indicators,
        session=SESSION,
        logger=demisto,
        verify=VERIFY
    )
    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    tags = argToList(demisto.params().get("feedTags", []))
    tlp_color = demisto.params().get("tlp_color")
    commands: dict[str, Callable] = {"test-module": module_command_test, "cybersixgill-get-indicators": get_indicators_command}
    try:
        if demisto.command() == "fetch-indicators":
            indicators = fetch_indicators_command(client, tags=tags, tlp_color=tlp_color)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(f"Error failed to execute {demisto.command()}, error: [{err}]")


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
