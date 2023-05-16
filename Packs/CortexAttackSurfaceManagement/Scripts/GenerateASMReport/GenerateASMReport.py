import json
import traceback
from base64 import b64decode
from typing import Any, Dict, List

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def build_report(template: List[Dict], alert_id: str, report_type: str) -> Dict:
    """Take a JSON template input and return a PDF Summary Report

    Args:
        template (List[Dict]): Python list of dicts built from args
        alert_id (str): the alert number
        report_type: whether it is summary or analysis report

    Returns:
        Dict: File Result object
    """
    if report_type == "summary":
        file_prefix = "asm_alert_investigation_summary"
    elif report_type == "analysis":
        file_prefix = "asm_alert_analysis_report"
    else:
        raise ValueError("available options are `summary` and `analysis`")
    # Convert Dict to json string
    template_str = json.dumps(template)
    # Encode json to b64 for SanePdfReports
    template_b64 = base64.b64encode(template_str.encode("utf8")).decode()
    # Convert json to PDF
    results = demisto.executeCommand(
        "SanePdfReports", {"sane_pdf_report_base64": template_b64, "raw-response": True}
    )
    pdf_b64 = results[0]["Contents"]["data"]
    # Decode returned b64 bytecode from SanePDF to write to PDF file
    pdf_raw = b64decode(pdf_b64)
    file_entry = fileResult(
        filename=file_prefix + "_" + alert_id + ".pdf",
        data=pdf_raw,
        file_type=EntryType.ENTRY_INFO_FILE,
    )

    return file_entry


def build_template(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build a template to be used to create Summary report

    Args:
        args (Dict[str, Any]): Demisto.args() object

    Returns:
        List[Dict[str, Any]]: Python list of dicts that will become the JSON template
    """
    cur_date = demisto.executeCommand("GetTime", {"dateFormat": "ISO"})[0]["Contents"]

    # banner
    header = demisto.executeCommand("getList", {"listName": "ReportHeader"})
    banner_img = header[0]['Contents']

    # Service Summary
    try:
        service_raw = execute_command('asm-get-external-service',
                                      {'service_id': args.get("asm_service_id", "Asset ID")})["reply"]["details"][0]
    except Exception:
        service_raw = {}
    # If response is list, only use the first entry.
    if isinstance(service_raw, list):
        service_raw = service_raw[0]

    # Asset details
    try:
        asset_raw = execute_command('asm-get-asset-internet-exposure',
                                    {'asm_id': args.get("asm_asset_id", "Asset ID")})["reply"]["details"][0]
    except Exception:
        asset_raw = {}
    # If response is list, only use the first entry.
    if isinstance(asset_raw, list):
        asset_raw = asset_raw[0]

    # See examples here for template: https://github.com/demisto/sane-reports/tree/master/templates
    if args.get('report_type') == "summary":
        remediation = args.get("asm_remediation", "No Remediation Information")
        if not isinstance(remediation, list):
            remediation = [remediation]
        template = [
            # Report headers
            {
                "type": "image",
                "data": banner_img,
                "layout": {
                    "rowPos": 1,
                    "columnPos": 1,
                    "alt": "Cortex",
                },
            },
            {
                "type": "header",
                "data": "ASM Investigation Summary Report",
                "layout": {
                    "rowPos": 2,
                    "columnPos": 2,
                    "style": {
                        "textAlign": "center",
                        "fontSize": 28,
                        "color": "black",
                        "background-color": "white",
                    },
                },
            },
            {
                "type": "text",
                "data": "Alert ID: ",
                "layout": {
                    "rowPos": 3,
                    "columnPos": 1,
                    "sectionStyle": {"width": 150},
                    "style": {
                        "textAlign": "left",
                        "font-weight": "bold",
                        "fontSize": 16,
                    },
                },
            },
            {
                "type": "text",
                "data": args.get("alert_id", "Alert ID"),
                "layout": {
                    "rowPos": 3,
                    "columnPos": 2,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                    },
                },
            },
            {
                "type": "date",
                "data": cur_date,
                "layout": {
                    "sectionStyle": {"width": 200},
                    "columnPos": 3,
                    "format": "YYYY-MM-DD HH:mm",
                    "rowPos": 3,
                    "style": {"fontSize": 14, "textAlign": "right"},
                },
            },
            {
                "type": "text",
                "data": "Alert Summary: ",
                "layout": {
                    "sectionStyle": {"width": 150},
                    "rowPos": 4,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "font-weight": "bold",
                        "fontSize": 16,
                    },
                },
            },
            {
                "type": "text",
                "data": args.get("alert_name", "Alert Name not found"),
                "layout": {
                    "rowPos": 4,
                    "columnPos": 2,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                    },
                },
            },
            {
                "type": "text",
                "data": "Alert Severity: ",
                "layout": {
                    "sectionStyle": {"width": 150},
                    "rowPos": 5,
                    "columnPos": 1,
                    "style": {"textAlign": "left", "font-weight": "bold", "fontSize": 16},
                },
            },
            {
                "type": "text",
                "data": args.get("alert_severityStr", "Severity"),
                "layout": {
                    "rowPos": 5,
                    "columnPos": 2,
                    "style": {
                        "textAlign": "left",
                        "font-weight": "bold",
                        "fontSize": 16,
                        "color": color_for_severity(
                            args.get("alert_severityStr", "Unknown")
                        ),
                    },
                },
            },
            {
                "type": "header",
                "data": "Alert Details",
                "layout": {
                        "rowPos": 6,
                        "columnPos": 1,
                        "style": {
                            "textAlign": "left",
                            "fontSize": 16,
                            "color": "black",
                            "background-color": "white",
                            "border-bottom": "5px solid #00cc66ff",
                        },
                },
            },
            {
                "type": "text",
                "data": args.get("alert_details", "Alert Details not found").replace("&#39;", "'"),
                "layout": {
                    "rowPos": 7,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "display": "flex",
                        "alignItems": "center",
                        "padding": "5px",
                        "fontSize": 12,
                    },
                },
            },
            # Service Summary
            {
                "type": "header",
                "data": "Service Details",
                "layout": {
                    "rowPos": 8,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                        "color": "black",
                        "background-color": "white",
                        "border-bottom": "5px solid #00cc66ff",
                    },
                },
            },
            {
                "type": "table",
                "data": service_format(service_raw),
                "layout": {
                    "rowPos": 9,
                    "columnPos": 1,
                    "tableColumns": [
                        "Field",
                        "Value"
                    ],
                    "classes": "striped stackable",
                },
            },
            # Asset Summary
            {
                "type": "header",
                "data": "Asset Details",
                "layout": {
                    "rowPos": 10,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                        "color": "black",
                        "background-color": "white",
                        "border-bottom": "5px solid #00cc66ff",
                    },
                },
            },
            {
                "type": "table",
                "data": asset_format(asset_raw),
                "layout": {
                    "rowPos": 11,
                    "columnPos": 1,
                    "tableColumns": [
                        "Field",
                        "Value"
                    ],
                    "classes": "striped stackable",
                },
            },
            {
                "type": "header",
                "data": "Remediation Taken",
                "layout": {
                    "rowPos": 12,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                        "color": "black",
                        "background-color": "white",
                        "border-bottom": "5px solid #00cc66ff",
                    },
                },
            },
            {
                "type": "table",
                "data": remediation,
                "layout": {
                    "rowPos": 13,
                    "columnPos": 1,
                    "tableColumns": [
                        "Action",
                        "ActionTimestamp",
                        "Outcome",
                        "OutcomeTimestamp",
                    ],
                    "classes": "striped stackable",
                },
            },
            # Evidence
            {
                "type": "header",
                "data": "Evidence and Investigation Artifacts",
                "layout": {
                    "rowPos": 14,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                        "color": "black",
                        "background-color": "#00cc66ff",
                    },
                },
            }
        ]

        placeholder = 15
        optional_order = ["asm_remediation_path_rule", "asm_service_owner", "asm_notification",
                          "asm_data_collection", "asm_private_ip", "asm_cloud", "asm_tags", "asm_system_ids"]
    elif args.get('report_type') == "analysis":
        template = [
            # Report headers
            {
                "type": "image",
                "data": banner_img,
                "layout": {
                    "rowPos": 1,
                    "columnPos": 1,
                    "alt": "Cortex",
                },
            },
            {
                "type": "header",
                "data": "ASM Analysis Report",
                "layout": {
                    "rowPos": 2,
                    "columnPos": 2,
                    "style": {
                        "textAlign": "center",
                        "fontSize": 28,
                        "color": "black",
                        "background-color": "white",
                    },
                },
            },
            {
                "type": "text",
                "data": "Alert ID: ",
                "layout": {
                    "rowPos": 3,
                    "columnPos": 1,
                    "sectionStyle": {"width": 150},
                    "style": {
                        "textAlign": "left",
                        "font-weight": "bold",
                        "fontSize": 16,
                    },
                },
            },
            {
                "type": "text",
                "data": args.get("alert_id", "Alert ID"),
                "layout": {
                    "rowPos": 3,
                    "columnPos": 2,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                    },
                },
            },
            {
                "type": "date",
                "data": cur_date,
                "layout": {
                    "sectionStyle": {"width": 200},
                    "columnPos": 3,
                    "format": "YYYY-MM-DD HH:mm",
                    "rowPos": 3,
                    "style": {"fontSize": 14, "textAlign": "right"},
                },
            },
            {
                "type": "text",
                "data": "Alert Summary: ",
                "layout": {
                    "sectionStyle": {"width": 150},
                    "rowPos": 4,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "font-weight": "bold",
                        "fontSize": 16,
                    },
                },
            },
            {
                "type": "text",
                "data": args.get("alert_name", "Alert Name not found"),
                "layout": {
                    "rowPos": 4,
                    "columnPos": 2,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                    },
                },
            },
            {
                "type": "text",
                "data": "Alert Severity: ",
                "layout": {
                    "sectionStyle": {"width": 150},
                    "rowPos": 5,
                    "columnPos": 1,
                    "style": {"textAlign": "left", "font-weight": "bold", "fontSize": 16},
                },
            },
            {
                "type": "text",
                "data": args.get("alert_severityStr", "Severity"),
                "layout": {
                    "rowPos": 5,
                    "columnPos": 2,
                    "style": {
                        "textAlign": "left",
                        "font-weight": "bold",
                        "fontSize": 16,
                        "color": color_for_severity(
                            args.get("alert_severityStr", "Unknown")
                        ),
                    },
                },
            },
            {
                "type": "header",
                "data": "Risk Description",
                "layout": {
                    "rowPos": 6,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                        "color": "black",
                        "background-color": "white",
                        "border-bottom": "5px solid #00cc66ff",
                    },
                },
            },
            {
                "type": "text",
                "data": args.get("alert_details", "Alert Details not found").replace("&#39;", "'"),
                "layout": {
                    "rowPos": 7,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "display": "flex",
                        "alignItems": "center",
                        "padding": "5px",
                        "fontSize": 12,
                    },
                },
            },
            # Service Summary
            {
                "type": "header",
                "data": "Service Details",
                "layout": {
                    "rowPos": 8,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                        "color": "black",
                        "background-color": "white",
                        "border-bottom": "5px solid #00cc66ff",
                    },
                },
            },
            {
                "type": "table",
                "data": service_format(service_raw),
                "layout": {
                    "rowPos": 9,
                    "columnPos": 1,
                    "tableColumns": [
                        "Field",
                        "Value"
                    ],
                    "classes": "striped stackable",
                },
            },
            # Asset Summary
            {
                "type": "header",
                "data": "Asset Details",
                "layout": {
                    "rowPos": 10,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                        "color": "black",
                        "background-color": "white",
                        "border-bottom": "5px solid #00cc66ff",
                    },
                },
            },
            {
                "type": "table",
                "data": asset_format(asset_raw),
                "layout": {
                    "rowPos": 11,
                    "columnPos": 1,
                    "tableColumns": [
                        "Field",
                        "Value"
                    ],
                    "classes": "striped stackable",
                },
            },
            # Evidence
            {
                "type": "header",
                "data": "Evidence and Investigation Artifacts",
                "layout": {
                    "rowPos": 12,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "fontSize": 16,
                        "color": "black",
                        "background-color": "#00cc66ff",
                    },
                },
            },
        ]

        placeholder = 13
        optional_order = ["asm_service_owner", "asm_private_ip", "asm_cloud", "asm_tags", "asm_system_ids"]

    optional_template = optional_report_fields(placeholder, optional_order, args)
    template.extend(optional_template)
    return template


def optional_report_fields(placeholder: int, optional_order: list, args: Dict) -> list:
    """Gets last report positional value, order of optional fields and Demisto.args()
    to determine what to append to report template.
    Args:
        placeholder (int): integer of the last
        optional_order (list): list of optional fields (inputs)
        args (Dict[str, Any]): Demisto.args() object
    Returns:
       List: List containing items to extend to template
    """
    optional_fields = {
        "asm_remediation_path_rule": {
            "header": "Remediation Rule Match",
            "description": "This section contains the Remediation Path Rule that matched on this particular alert.",
            "columns": [
                "rule_name",
                "criteria",
                "created_by",
                "action"
            ]
        },
        "asm_notification": {
            "header": "Notifications Sent",
            "description": "This section contains the notification sent from the playbook (email or ticketing system).",
            "columns": [
                "Type",
                "Value",
                "URL",
                "Timestamp"
            ]
        },
        "asm_data_collection": {
            "header": "Data Collected from Owner",
            "description": "This section contains information on the data collection task completed in the playbook.",
            "columns": [
                "Options",
                "Selected",
                "Answerer",
                "Timestamp"
            ]
        },
        "asm_system_ids": {
            "header": "Related System Identifiers",
            "description": "This section contains any related system records from other IT/Security systems"
                           "as well as links where available.",
            "columns": [
                "Type",
                "ID",
                "Link"
            ]
        },
        "asm_tags": {
            "header": "Object Tag Information",
            "description": "Any related tags or labels found in other IT/Security systems during "
                           "the investigation are recorded here.",
            "columns": [
                "Key",
                "Value",
                "Source"
            ]
        },
        "asm_cloud": {
            "header": "Cloud Asset Information",
            "description": "Any additional cloud details discovered during the investigation are lists in this section.",
            "columns": [
                "Provider",
                "Organization",
                "Project",
                "Region",
                "Other"
            ]
        },
        "asm_private_ip": {
            "header": "Private IP Addresses",
            "description": "Any identified private IP addresses that are known to be related to "
                           "the asset being investigated are recorded here.",
            "columns": [
                "Source",
                "IP"
            ]
        },
        "asm_service_owner": {
            "header": "Service Owner Information",
            "description": "This section contains all potential service owners identified during the investigation.",
            "columns": [
                "Name",
                "Email",
                "Source",
                "Timestamp"
            ]
        },
    }
    extend_template = []
    for field in optional_order:
        if args.get(field):
            extend_template.append(
                {
                    "type": "header",
                    "data": optional_fields[field]["header"],
                    "layout": {
                        "rowPos": placeholder,
                        "columnPos": 1,
                        "style": {
                            "textAlign": "left",
                            "fontSize": 16,
                            "color": "black",
                            "background-color": "white",
                            "border-bottom": "5px solid #00cc66ff",
                        },
                    },
                })
            extend_template.append({
                "type": "text",
                "data": optional_fields[field]["description"],
                "layout": {
                    "rowPos": placeholder + 1,
                    "columnPos": 1,
                    "style": {
                        "textAlign": "left",
                        "display": "flex",
                        "alignItems": "center",
                        "fontSize": 10,
                    },
                },
            })
            data = args.get(field)

            if data is not None and not isinstance(data, list):
                data = [data]
            extend_template.append({
                "type": "table",
                "data": data,
                "layout": {
                    "rowPos": placeholder + 2,
                    "columnPos": 1,
                    "tableColumns": optional_fields[field]["columns"],
                    "classes": "striped stackable",
                },
            })
            placeholder = placeholder + 3
    return extend_template


def color_for_severity(severity: str) -> str:
    sev_map = {"low": "green", "medium": "gold", "high": "red", "critical": "maroon"}
    return sev_map.get(severity.lower(), "black")


def RPR_criteria(criteria: Any) -> Any:
    if criteria:
        criteria_dict = json.loads(criteria)
        statements = []
        for entry in criteria_dict:
            statements.append(f"({entry.get('field')} {'=' if entry.get('operator') == 'eq' else '!='} {entry.get('value')})")
        return " AND ".join(statements)
    else:
        return None


def service_format(service_raw: Dict[str, Any]) -> List:
    """Gets raw service information and formats key information for table.
    Args:
        service_raw (Dict): raw response from services API.  Blank indicators error.
    Returns:
       List: List of dictionaries of key/value pairs to add to template.
    """
    if service_raw == {}:
        service_message = [{"Field": "Unable to pull service details",
                            "Value": "Please make sure that the Cortex Attack Surface Management\
                                integration has been configured and is passing test."}]
        return service_message
    # create a condensed service object
    service_details = [
        {
            "Field": "Service Type",
            "Value": service_raw.get("service_type", "N/A")
        },
        {
            "Field": "Service Name",
            "Value": service_raw.get("service_name", "N/A")
        },
        {
            "Field": "Active Classifications",
            "Value": service_raw.get("active_classifications", "N/A")
        },
        {
            "Field": "Business Units",
            "Value": service_raw.get("business_units", "N/A")
        },
        {
            "Field": "Provider",
            "Value": service_raw.get("externally_detected_providers", "N/A")
        },
        {
            "Field": "IP Addresses",
            "Value": service_raw.get("ip_address", "N/A")
        },
        {
            "Field": "Port",
            "Value": service_raw.get("port", "N/A")
        },
        {
            "Field": "Protocol",
            "Value": service_raw.get("protocol", "N/A")
        },
        {
            "Field": "First Observed",
            "Value": datetime.utcfromtimestamp(int(service_raw["first_observed"] / 1000)).strftime('%Y-%m-%d')
        },
        {
            "Field": "Last Observed",
            "Value": datetime.utcfromtimestamp(int(service_raw["last_observed"] / 1000)).strftime('%Y-%m-%d')
        }

    ]

    if service_raw.get("domain"):
        service_details.append({
            "Field": "Domains",
            "Value": service_raw.get("domain")
        })

    if service_raw.get("details", {}).get("tlsVersions"):
        service_details.append({
            "Field": "TLS",
            "Value": service_raw.get("details", {}).get("tlsVersions")[0].get('tlsVersion')
        })

    return service_details


def asset_format(asset_raw: Dict[str, Any]) -> List:
    """Gets raw asset information and formats key information for table.
    Args:
        asset_raw (Dict): raw response from asset API.  Blank indicators error.
    Returns:
       List: List of dictionaries of key/value pairs to add to template.
    """
    if asset_raw == {}:
        asset_message = [{"Field": "Unable to pull asset details",
                          "Value": "Please make sure that the Cortex Attack Surface Management integration has\
                                    been configured and is passing test."}]
        return asset_message
    asset_details = [
        {
            "Field": "Asset Name",
            "Value": asset_raw.get("name")
        },
        {
            "Field": "Business Units",
            "Value": ", ".join(asset_raw.get("business_units", ["n/a"]))
        },
        {
            "Field": "Asset Type",
            "Value": asset_raw.get("type")
        },
        {
            "Field": "Detected Services on Asset",
            "Value": ", ".join(asset_raw.get("active_external_services_types", ["n/a"]))
        }
    ]

    if len(asset_raw.get("ips", [])) > 0:
        asset_details.append({
            "Field": "IPs",
            "Value": ", ".join(asset_raw.get("ips", ["n/a"]))
        })

    if asset_raw.get("domain", []):
        asset_details.append({
            "Field": "Domains",
            "Value": asset_raw["domain"]
        })

    if len(asset_raw.get("details", {}).get("ip_ranges", {}).keys()) > 0:
        for k in asset_raw.get("details", {}).get("ip_ranges", {}).keys():
            first_ip = f'{asset_raw.get("details", {}).get("ip_ranges").get(k).get("FIRST_IP")}'
            last_ip = f'{asset_raw.get("details", {}).get("ip_ranges").get(k).get("LAST_IP")}'
            asset_details.append({
                "Field": "Associated IP Range",
                "Value": f'{first_ip} - {last_ip}'
            })
            if len(asset_raw.get("details", {}).get("ip_ranges", {}).get(k, {}).get("EXPLAINERS", [])) > 0:
                asset_details.append({
                    "Field": "IP Range Attribution Details",
                    "Value": ", ".join(asset_raw.get("details", {}).get("ip_ranges", {}).get(k).get("EXPLAINERS"))
                })

    if asset_raw.get("first_observed", []):
        asset_details.append({
            "Field": "First Observed",
            "Value": datetime.utcfromtimestamp(int(asset_raw["first_observed"] / 1000)).strftime('%Y-%m-%d')
        })

    if asset_raw.get("last_observed", []):
        asset_details.append({
            "Field": "Last Observed",
            "Value": datetime.utcfromtimestamp(int(asset_raw["last_observed"] / 1000)).strftime('%Y-%m-%d')
        })

    if asset_raw.get("explainers", []):
        asset_details.append({
            "Field": "Explainers",
            "Value": ", ".join(asset_raw.get("explainers", {}))
        })

    return asset_details


""" MAIN FUNCTION """


def main():

    try:
        template = build_template(demisto.args())
        return_results(build_report(template, demisto.args().get("alert_id", ""), demisto.args().get('report_type')))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute Generate Summary Report. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
