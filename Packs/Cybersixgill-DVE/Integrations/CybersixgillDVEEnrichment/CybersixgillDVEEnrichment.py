import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

import requests

from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest
from sixgill.sixgill_enrich_client import SixgillEnrichClient

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

""" CONSTANTS """
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def test_module(client_id, client_secret, channel_code, session, verify):
    """
    Performs basic Auth request
    """
    response = session.send(
        request=SixgillAuthRequest(client_id, client_secret, channel_code).prepare(),
        verify=verify,
    )
    if not response.ok:
        raise Exception("Auth request failed - please verify client_id, and client_secret.")
    return "ok"


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
        indicator["value"] = ext_id
        indicator["Description"] = stix_obj.get("description", "")
        indicator["Created"] = stix_obj.get("created", "")
        indicator["Modified"] = stix_obj.get("modified", "")
        indicator["Cybersixgill_DVE_score_current"] = score_obj.get("current", "")
        indicator["Cybersixgill_DVE_score_highest_ever_date"] = score_obj.get("highest", {}).get("date", "")
        indicator["Cybersixgill_DVE_score_highest_ever"] = score_obj.get("highest", {}).get("value", "")
        indicator["Cybersixgill_Previously_exploited_probability"] = score_obj.get("previouslyExploited", "")
        indicator["Previous_Level"] = event_obj.get("prev_level", "")
        indicator["CVSS_3_1_score"] = nvd_obj_v3.get("exploitabilityScore", "")
        indicator["CVSS_3_1_severity"] = nvd_obj_v3.get("severity", "")
        indicator["NVD_Link"] = nvd_obj.get("link", "")
        indicator["NVD_last_modified_date"] = nvd_obj.get("modified", "")
        indicator["NVD_publication_date"] = nvd_obj.get("published", "")
        indicator["CVSS_2_0_score"] = nvd_obj_v2.get("exploitabilityScore", "")
        indicator["CVSS_2_0_severity"] = nvd_obj_v2.get("severity", "")
        indicator["NVD_Vector_V2_0"] = nvd_obj_v2.get("vector", "")
        indicator["NVD_Vector_V3_1"] = nvd_obj_v3.get("vector", "")
        indicator["rawJSON"] = stix_obj
    except Exception as err:
        err_msg = f"Error in DVE Enrichment Integration [{err}]\nTrace:\n{traceback.format_exc()}"
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
    readable_output = tableToMarkdown("Enriched results for cve_id:", final_data_list)

    command_results.append(
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="Sixgill.CVE",
            outputs_key_field="CVE_ID",
            outputs=final_data_list,
        )
    )

    return command_results


def main():
    channel_code = "d5cd46c205c20c87006b55a18b106428"
    params = demisto.params()
    command = demisto.command()
    verify = not params.get("insecure", True)
    session = requests.Session()
    session.proxies = handle_proxy()

    client = SixgillEnrichClient(params.get("client_id"), params.get("client_secret"), channel_code, demisto,
                                 session, verify)

    LOG(f"Command being called is {demisto.command()}")
    try:

        if command == "cybersixgill-cve-enrich":
            return_results(cve_enrich_command(client, demisto.args()))
        elif command == "test-module":
            return_results(
                test_module(
                    params.get("client_id"), params.get("client_secret"), channel_code, session, verify
                )
            )
    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
