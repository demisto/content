import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *

""" IMPORTS """

import requests
from sixgill.sixgill_enrich_client import SixgillEnrichClient
from sixgill.sixgill_request_classes.sixgill_auth_request import SixgillAuthRequest

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


def cve_enrich_remediation_command(client: SixgillEnrichClient, args) -> List[CommandResults]:
    cve_ids = argToList(args.get("cve_id"))

    command_results: List[CommandResults] = []
    remediations = []
    for cve_id in cve_ids:
        dve_remediations = client.enrich_dve_remediation(cve_id)
        for dve_remediation in dve_remediations:
            if any([dve_remediation.get("advisory"), dve_remediation.get("description"), dve_remediation.get("solutions")]):
                remediations.append(
                    {
                        "Value": cve_id,
                        "Advisory": dve_remediation.get("advisory", ""),
                        "Description": dve_remediation.get("description", ""),
                        "Solutions": dve_remediation.get("solutions", ""),
                    }
                )

    readable_output = tableToMarkdown("Enriched results for cve_id:", remediations)

    command_results.append(
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="Sixgill.CVE",
            outputs_key_field="CVE_ID",
            outputs=remediations,
        )
    )
    return command_results


def main():
    channel_code = "7457a04d972fceb8e0cc2192ba4abc66" if is_xsiam() else "7698e8287dfde53dcd13082be750a85a"
    params = demisto.params()
    command = demisto.command()
    verify = not params.get("insecure", True)
    session = requests.Session()
    session.proxies = handle_proxy()

    client = SixgillEnrichClient(params.get("client_id"), params.get("client_secret"), channel_code, demisto, session, verify)

    LOG(f"Command being called is {demisto.command()}")
    try:
        if command == "cybersixgill-cve-enrich":
            return_results(cve_enrich_command(client, demisto.args()))
        elif command == "cybersixgill-cve-remediation":
            return_results(cve_enrich_remediation_command(client, demisto.args()))
        elif command == "test-module":
            return_results(test_module(params.get("client_id"), params.get("client_secret"), channel_code, session, verify))
    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
