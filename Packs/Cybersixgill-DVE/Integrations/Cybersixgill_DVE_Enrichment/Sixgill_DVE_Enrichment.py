import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
import dateparser
import requests

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_enrich_client import SixgillEnrichClient

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def test_module_command(client_id, client_secret, channel_code, session, verify):
    """
    Performs basic Auth request
    """
    response = session.send(
        request=SixgillAuthRequest(
            client_id, client_secret, channel_code
        ).prepare(),
        verify=verify,
    )
    if not response.ok:
        raise Exception("Auth request failed - please verify client_id, and client_secret.")
    return "ok"


def create_fields(stix_obj, event_obj, nvd_obj, nvd_obj_v2, nvd_obj_v3, score_obj, ext_id):
    fields = {}
    try:
        fields = {
            "Description": stix_obj.get("description", ""),
            "Created": stix_obj.get("created", ""),
            "Modified": stix_obj.get("modified", ""),
            "External id": ext_id,
            "Sixgill DVE score - current": score_obj.get("current", ""),
            "Sixgill DVE score - highest ever date": score_obj.get("highest", {}).get("date", ""),
            "Sixgill DVE score - highest ever": score_obj.get("highest", {}).get("value", ""),
            "Sixgill - Previously exploited probability": score_obj.get("previouslyExploited", ""),
            "Event Name": event_obj.get("name", ""),
            "Event Type": event_obj.get("type", ""),
            "Event Action": event_obj.get("action", ""),
            "Previous Level": event_obj.get("prev_level", ""),
            "Event Description": event_obj.get("description", ""),
            "Event Datetime": event_obj.get("event_datetime", ""),
            "CVSS 3.1 score": nvd_obj_v3.get("exploitabilityScore", ""),
            "CVSS 3.1 severity": nvd_obj_v3.get("severity", ""),
            "NVD Link": nvd_obj.get("link", ""),
            "NVD - last modified date": nvd_obj.get("modified", ""),
            "NVD - publication date": nvd_obj.get("published", ""),
            "CVSS 2.0 score": nvd_obj_v2.get("exploitabilityScore", ""),
            "CVSS 2.0 severity": nvd_obj_v2.get("severity", ""),
            "NVD Vector - V2.0": nvd_obj_v2.get("vector", ""),
            "NVD Vector - V3.1": nvd_obj_v3.get("vector", ""),
        }
    except Exception as err:
        err_msg = f'Error in DVE Enrichment Integration [{err}]\nTrace:\n{traceback.format_exc()}'
        raise DemistoException(err_msg)
    return fields


def stix_to_indicator(stix_obj):
    indicator: Dict[str, Any] = {}
    try:
        ext_obj = stix_obj.get("external_references", [])
        ext_id = ""
        if ext_obj and ext_obj[0]:
            ext_id = ext_obj[0].get("external_id")
        event_obj = stix_obj.get("x_sixgill_info", {}).get("event", {})
        nvd_obj = stix_obj.get("x_sixgill_info", {}).get("nvd", {})
        nvd_obj_v2 = stix_obj.get("x_sixgill_info", {}).get("nvd", {}).get("v2", {})
        nvd_obj_v3 = stix_obj.get("x_sixgill_info", {}).get("nvd", {}).get("v3", {})
        score_obj = stix_obj.get("x_sixgill_info", {}).get("score", {})
        fields = create_fields(stix_obj, event_obj, nvd_obj, nvd_obj_v2, nvd_obj_v3, score_obj, ext_id)
        indicator["value"] = ext_id
        indicator["Overview"] = fields
        indicator["rawJSON"] = {"value": ext_id, "type": "CVE"}
        indicator["rawJSON"].update(stix_obj)
    except Exception as err:
        err_msg = f'Error in DVE Enrichment Integration [{err}]\nTrace:\n{traceback.format_exc()}'
        raise DemistoException(err_msg)
    return indicator


def cve_enrich_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    cve_ids = argToList(args.get("cve_id"))
    if len(cve_ids) == 0:
        raise ValueError("CVE_ID(s) not specified")

    command_results: List[CommandResults] = []
    final_data_list = []
    for cve_id in cve_ids:
        cve_id_data = client.enrich_dve(cve_id)
        final_data = stix_to_indicator(cve_id_data)
        final_data_list.append(final_data)
    readable_output = tableToMarkdown("CVE_ID", final_data_list)

    command_results.append(
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="Sixgill.CVE_ID",
            outputs_key_field="CVE_ID",
            outputs=final_data_list,
        )
    )

    return command_results


def main():
    channel_code = "d5cd46c205c20c87006b55a18b106428"
    verify = not demisto.params().get("insecure", True)
    session = requests.Session()

    session.proxies = handle_proxy()

    client = SixgillEnrichClient(
        demisto.params()["client_id"], demisto.params()["client_secret"], channel_code, demisto, session, verify
    )

    LOG(f'Command being called is {demisto.command()}')
    try:

        if demisto.command() == 'cve':
            return_results(cve_enrich_command(client, demisto.args()))
        else:
            return_results(
                test_module_command(demisto.params()["client_id"], demisto.params()["client_secret"], channel_code,
                                    session, verify))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
