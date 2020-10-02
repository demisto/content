import demistomock as demisto
from CommonServerPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

import json
import dateparser

from argus_cli.utils import formatting  # Common helper for creating nice outputs
from argus_cli.settings import settings

from argus_api.api.currentuser.v1.user import get_current_user

from argus_api.api.cases.v2.case import (
    add_case_tag,
    add_comment,
    advanced_case_search,
    close_case,
    create_case,
    delete_case,
    delete_comment,
    download_attachment,
    edit_comment,
    get_attachment,
    get_case_metadata_by_id,
    list_case_attachments,
    list_case_tags,
    list_case_comments,
    remove_case_tag_by_key_value,
    update_case,
)

from argus_api.api.events.v1.case.case import get_events_for_case
from argus_api.api.events.v1.aggregated import list_aggregated_events
from argus_api.api.events.v1.payload import get_payload
from argus_api.api.events.v1.pcap import get_pcap

from argus_api.api.pdns.v3.search import search_records

from argus_api.api.reputation.v1.observation import (
    fetch_observations_for_domain,
    fetch_observations_for_i_p,
)

from typing import List, Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """


DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_INCIDENTS_TO_FETCH = 50
FETCH_TAG = demisto.params().get("fetch_tag")

""" CLIENT CLASS """


""" HELPER FUNCTIONS """


def set_argus_settings(api_key, api_url):
    settings["api"]["api_key"] = api_key
    settings["api"]["api_url"] = api_url


def argus_priority_to_demisto_severity(priority: str) -> int:
    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get(priority, 0)


def argus_status_to_demisto_status(status: str) -> int:
    mapping = {
        "pendingCustomer": 0,
        "pendingSoc": 0,
        "pendingVendor": 0,
        "pendingClose": 0,
        "workingSoc": 1,
        "workingCustomer": 1,
        "closed": 2,
    }
    return mapping.get(status, 0)


""" COMMAND FUNCTIONS """


def test_module_command() -> str:
    response = get_current_user()
    if response["responseCode"] == 200:
        return "ok"
    else:
        return_error(
            "Unable to communicate with Argus API", response["responseCode"], response
        )


def fetch_incidents(last_run: dict, first_fetch_period: str):
    raise NotImplementedError


def add_case_tag_command(args: Dict[str, Any]) -> CommandResults:
    case_id = args.get("case_id", None)
    key = args.get("key", None)
    value = args.get("value", None)
    if not case_id:
        raise ValueError("case_id not specified")
    if not key:
        raise ValueError("key not specified")
    if not value:
        raise ValueError("value not specified")
    tag = {"key": key, "value": value}
    result = add_case_tag(caseID=case_id, tags=tag)
    # tags = {key: result['data'][0][key] for key in result['data'][0].keys() & {'key', 'value', 'addedTimestamp'}}
    headers = ["key", "value", "addedTimestamp"]
    readable_output = tableToMarkdown(
        f"#{case_id}: Tags", result["data"][0], headers=headers
    )

    return CommandResults(readable_output=readable_output, outputs=result)


def add_comment_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def advanced_case_search_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def close_case_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def create_case_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def delete_case_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def delete_comment_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def download_attachment_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def edit_comment_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def get_attachment_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def get_case_metadata_by_id_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def list_case_attachments_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def list_case_tags_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def list_case_comments_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def remove_case_tag_by_key_value_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def update_case_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def get_events_for_case_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def list_aggregated_events_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def get_payload_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def get_pcap_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def search_records_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def fetch_observations_for_domain_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


def fetch_observations_for_i_p_command(args: Dict[str, Any]) -> CommandResults:
    raise NotImplementedError


""" MAIN FUNCTION """


def main() -> None:
    # TODO test argus-cli
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    first_fetch_period = demisto.params().get("first_fetch_period", "1 day")

    demisto.debug(f"Command being called is {demisto.command()}")
    try:

        set_argus_settings(
            demisto.params().get("api_key"), demisto.params().get("api_url")
        )

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module_command())

        elif demisto.command() == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                last_run=demisto.getLastRun(),
                first_fetch_period=first_fetch_period,
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == "argus_add_case_tag":
            return_results(add_case_tag_command(demisto.args()))

        elif demisto.command() == "argus_add_comment":
            return_results(add_comment_command(demisto.args()))

        elif demisto.command() == "argus_advanced_case_search":
            return_results(advanced_case_search_command(demisto.args()))

        elif demisto.command() == "argus_close_case":
            return_results(close_case_command(demisto.args()))

        elif demisto.command() == "argus_create_case":
            return_results(create_case_command(demisto.args()))

        elif demisto.command() == "argus_delete_case":
            return_results(delete_case_command(demisto.args()))

        elif demisto.command() == "argus_delete_comment":
            return_results(delete_comment_command(demisto.args()))

        elif demisto.command() == "argus_download_attachment":
            return_results(download_attachment_command(demisto.args()))

        elif demisto.command() == "argus_edit_comment":
            return_results(edit_comment_command(demisto.args()))

        elif demisto.command() == "argus_get_attachment":
            return_results(get_attachment_command(demisto.args()))

        elif demisto.command() == "argus_get_case_metadata_by_id":
            return_results(get_case_metadata_by_id_command(demisto.args()))

        elif demisto.command() == "argus_list_case_attachments":
            return_results(list_case_attachments_command(demisto.args()))

        elif demisto.command() == "argus_list_case_tags":
            return_results(list_case_tags_command(demisto.args()))

        elif demisto.command() == "argus_list_case_comments":
            return_results(list_case_comments_command(demisto.args()))

        elif demisto.command() == "argus_remove_case_tag_by_key_value":
            return_results(remove_case_tag_by_key_value_command(demisto.args()))

        elif demisto.command() == "argus_update_case":
            return_results(update_case_command(demisto.args()))

        elif demisto.command() == "argus_get_events_for_case":
            return_results(get_events_for_case_command(demisto.args()))

        elif demisto.command() == "argus_list_aggregated_events":
            return_results(list_aggregated_events_command(demisto.args()))

        elif demisto.command() == "argus_get_payload":
            return_results(get_payload_command(demisto.args()))

        elif demisto.command() == "argus_get_pcap":
            return_results(get_pcap_command(demisto.args()))

        elif demisto.command() == "argus_search_records":
            return_results(search_records_command(demisto.args()))

        elif demisto.command() == "argus_fetch_observations_for_domain ":
            return_results(fetch_observations_for_domain_command(demisto.args()))

        elif demisto.command() == "argus_fetch_observations_for_i_p":
            return_results(fetch_observations_for_i_p_command(demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
