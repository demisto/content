import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def get_asset_id_for_ip(ip):
    resp = demisto.executeCommand("qualys-host-list", {"ips": ip})
    if isError(resp[0]):
        demisto.results(resp)
        sys.exit(0)

    if isinstance(resp_dict := resp[0], dict) and isinstance(xml_string := resp_dict["Contents"], str):
        json_string: str = xml2json(xml_string)
        asset_id = demisto.get(json.loads(json_string), "HOST_LIST_OUTPUT.RESPONSE.HOST_LIST.HOST.ID")
    else:
        asset_id = demisto.get(resp[0], "Contents.HOST_LIST_OUTPUT.RESPONSE.HOST_LIST.HOST.ID")

    return asset_id


def main():
    incident_type = demisto.args().get("incidentType", "Vulnerability")
    max_file_size = int(demisto.args().get("maxFileSize", 1024**2))
    min_severity = int(demisto.args().get("minSeverity", 1))

    file_entry = demisto.getFilePath(demisto.args().get("entryID"))
    with open(file_entry["path"]) as f:
        data = f.read(max_file_size)

    if data:
        report = json.loads(xml2json(data))

        generation_date = demisto.get(report, "ASSET_DATA_REPORT.HEADER.GENERATION_DATETIME")

        # Get asset list
        asset_list = demisto.get(report, "ASSET_DATA_REPORT.HOST_LIST.HOST")
        if not asset_list:
            demisto.results(
                {"Type": entryTypes["note"], "ContentsFormat": formats["text"], "Contents": "No vulnerable assets were found"}
            )
            sys.exit(0)

        if not isinstance(asset_list, list):
            asset_list = [asset_list]

        # Get QIDs only if over relevant severity
        general_vulnerabilities = argToList(demisto.get(report, "ASSET_DATA_REPORT.GLOSSARY.VULN_DETAILS_LIST.VULN_DETAILS"))
        if not isinstance(general_vulnerabilities, list):
            general_vulnerabilities = [general_vulnerabilities]

        # Get list of QID with severity >= min_severity
        qid_severity = [
            demisto.get(vulnerability, "QID.#text")
            for vulnerability in general_vulnerabilities
            if demisto.get(vulnerability, "SEVERITY") and (int(demisto.get(vulnerability, "SEVERITY")) >= min_severity)
        ]

        for asset in asset_list:
            # Get Asset ID from Qualys
            ip = demisto.get(asset, "IP")
            if not ip:
                demisto.results(
                    {
                        "Type": entryTypes["error"],
                        "ContentsFormat": formats["text"],
                        "Contents": "No IP was found for asset {0}".format(str(asset)),
                    }
                )
                sys.exit(0)

            asset_id = get_asset_id_for_ip(ip)
            if not asset_id:
                demisto.results(
                    {
                        "Type": entryTypes["error"],
                        "ContentsFormat": formats["text"],
                        "Contents": "No ID was found for asset {0}".format(str(asset)),
                    }
                )
                sys.exit(0)

            # Get Asset vulnerability list
            vulnerabilities = argToList(demisto.get(asset, "VULN_INFO_LIST.VULN_INFO"))
            if not isinstance(vulnerabilities, list):
                vulnerabilities = [vulnerabilities]

            qids = map(lambda vulnerability: demisto.get(vulnerability, "QID.#text"), vulnerabilities)

            # Get only the QIDs that exists in asset and has severity >= min_severity
            qids = list(set(qids) & set(qid_severity))

            for qid in qids:
                # Search for existing open incidents with the same Vendor ID and Asset ID.
                # Will open a new incident only if such an incident not exists.
                resp = demisto.executeCommand(
                    "getIncidents", {"query": "vendorid: {0} and assetid: {1} and --status:Closed".format(qid, asset_id)}
                )
                if isError(resp[0]):
                    demisto.results(resp)
                    sys.exit(0)

                incident_number = demisto.get(resp[0], "Contents.total")

                try:
                    incident_number = int(incident_number)
                except Exception:
                    demisto.results(
                        {
                            "Type": entryTypes["error"],
                            "ContentsFormat": formats["text"],
                            "Contents": "Error while searching the incident repository",
                        }
                    )
                    sys.exit(0)

                if incident_number == 0:
                    # Create incident
                    demisto.executeCommand(
                        "createNewIncident",
                        {
                            "name": "Vulnerability - Asset {0} QID {1} - {2}".format(asset_id, qid, generation_date),
                            "vendorid": str(qid),
                            "type": incident_type,
                            "assetid": str(asset_id),
                        },
                    )

        demisto.results("Done.")
    else:
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": "No data could be read."})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
