import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import traceback
import json
from typing import Any, List, Dict
from base64 import b64decode


def build_report(template: List[Dict]) -> Dict:
    """Take a JSON template input and return a PDF Summary Report

    Args:
        template (List[Dict]): Python list of dicts built from args

    Returns:
        Dict: File Result object
    """

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
        filename="report.pdf", data=pdf_raw, file_type=EntryType.ENTRY_INFO_FILE
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

    # Grab ASM args from demisto.args()
    asm_args = get_asm_args(args)

    asm_tag = []
    for tag in asm_args["asmtags"]:
        # Check if each tag is properly formatted already
        if tag.keys() == {'Key', 'Value', 'Source'}:
            asm_tag.append(tag)
        else:
            tag_obj = json.loads(tag["Name"])
            asm_tag.append(
                {"Key": tag_obj["Key"], "Value": tag_obj["Value"], "Source": tag["Source"]}
            )

    # See examples here for template: https://github.com/demisto/sane-reports/tree/master/templates
    template = [
        {
            "type": "header",
            "data": "Investigation Summary Report",
            "layout": {
                "rowPos": 1,
                "columnPos": 1,
                "style": {"textAlign": "center", "fontSize": 32},
            },
        },
        {
            "type": "text",
            "data": args.get("alert_name", "Alert Name Here"),
            "layout": {
                "rowPos": 2,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "display": "flex",
                    "alignItems": "center",
                    "padding": "20px",
                    "fontSize": 16,
                },
            },
        },
        {
            "type": "date",
            "data": cur_date,
            "layout": {
                "columnPos": 2,
                "format": "YYYY-MM-DD",
                "rowPos": 2,
                "style": {"fontSize": 16, "fontStyle": "italic", "textAlign": "right"},
            },
        },
        {
            "type": "header",
            "data": "Remediation Taken",
            "layout": {
                "rowPos": 3,
                "columnPos": 1,
                "style": {"textAlign": "left", "fontSize": 16},
            },
        },
        {
            "type": "table",
            "data": asm_args["asmremediation"],
            "layout": {
                "rowPos": 4,
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
        {
            "type": "header",
            "data": "Alert Details",
            "layout": {
                "rowPos": 5,
                "columnPos": 1,
                "style": {"textAlign": "left", "fontSize": 16},
            },
        },
        {
            "type": "text",
            "data": args.get("alert_details", "Alert Details Here"),
            "layout": {
                "rowPos": 6,
                "columnPos": 1,
                "style": {
                    "textAlign": "left",
                    "display": "flex",
                    "alignItems": "center",
                    "padding": "20px",
                    "fontSize": 12,
                },
            },
        },
        {
            "type": "header",
            "data": "Service Owner Information",
            "layout": {
                "rowPos": 7,
                "columnPos": 1,
                "style": {"textAlign": "left", "fontSize": 16},
            },
        },
        {
            "type": "table",
            "data": asm_args["asmserviceowner"],
            "layout": {
                "rowPos": 8,
                "columnPos": 1,
                "tableColumns": ["Name", "Email", "Source", "Timestamp"],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Notifications Sent",
            "layout": {
                "rowPos": 9,
                "columnPos": 1,
                "style": {"textAlign": "left", "fontSize": 16},
            },
        },
        {
            "type": "table",
            "data": asm_args["asmnotification"],
            "layout": {
                "rowPos": 10,
                "columnPos": 1,
                "tableColumns": ["Type", "Value", "URL", "Timestamp"],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Data Collected from Owner",
            "layout": {
                "rowPos": 11,
                "columnPos": 1,
                "style": {"textAlign": "left", "fontSize": 16},
            },
        },
        {
            "type": "table",
            "data": asm_args["asmdatacollection"],
            "layout": {
                "rowPos": 12,
                "columnPos": 1,
                "tableColumns": ["Options", "Selected", "Answerer", "Timestamp"],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Private IP Addresses",
            "layout": {
                "rowPos": 13,
                "columnPos": 1,
                "style": {"textAlign": "left", "fontSize": 16},
            },
        },
        {
            "type": "table",
            "data": asm_args["asmprivateip"],
            "layout": {
                "rowPos": 14,
                "columnPos": 1,
                "tableColumns": ["Source", "IP"],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Cloud Asset Information",
            "layout": {
                "rowPos": 15,
                "columnPos": 1,
                "style": {"textAlign": "left", "fontSize": 16},
            },
        },
        {
            "type": "table",
            "data": asm_args["asmcloud"],
            "layout": {
                "rowPos": 16,
                "columnPos": 1,
                "tableColumns": [
                    "Provider",
                    "Organization",
                    "Project",
                    "Region",
                    "Other",
                ],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Object Tag Information",
            "layout": {
                "rowPos": 17,
                "columnPos": 1,
                "style": {"textAlign": "left", "fontSize": 16},
            },
        },
        {
            "type": "table",
            "data": asm_tag,
            "layout": {
                "rowPos": 18,
                "columnPos": 1,
                "tableColumns": [
                    "Key",
                    "Value",
                    "Source",
                ],
                "classes": "striped stackable",
            },
        },
        {
            "type": "header",
            "data": "Related System Identifiers",
            "layout": {
                "rowPos": 19,
                "columnPos": 1,
                "style": {"textAlign": "left", "fontSize": 16},
            },
        },
        {
            "type": "table",
            "data": asm_args["asmsystemids"],
            "layout": {
                "rowPos": 20,
                "columnPos": 1,
                "tableColumns": [
                    "Type",
                    "ID",
                    "Link",
                ],
                "classes": "striped stackable",
            },
        },
    ]

    return template


def get_asm_args(
    args: Dict[str, Any]
) -> Dict[str, Any]:
    """Get relevant ASM Arguments & Keys for Report template

    Args:
        args (Dict[str, Any]): Demisto.args() object

    Returns:
        Dict[str, Any]: Dictionary containing ASM Args in KV
    """

    # Set up default object for any empty arguments
    asm_args: Dict[str, Any] = {
        "asmserviceowner": args.get("asmserviceowner")
        if args.get("asmserviceowner")
        else {"Email": "n/a", "Name": "n/a", "Source": "n/a", "Timestamp": "n/a"},
        "asmcloud": (
            args.get("asmcloud")
            if args.get("asmcloud")
            else {
                "Organization": "n/a",
                "Other": "n/a",
                "Project": "n/a",
                "Provider": "n/a",
                "Region": "n/a",
            }
        ),
        "asmdatacollection": args.get("asmdatacollection")
        if args.get("asmdatacollection")
        else {
            "Answerer": "n/a",
            "Options": "n/a",
            "Selected": "n/a",
            "Timestamp": "n/a",
        },
        "asmnotification": args.get("asmnotification")
        if args.get("asmnotification")
        else {
            "Timestamp": "n/a",
            "Type": "n/a",
            "Url": "n/a",
            "Value": "n/a",
        },
        "asmprivateip": args.get("asmprivateip")
        if args.get("asmprivateip")
        else {"IP": "n/a", "Source": "n/a"},
        "asmremediation": args.get("asmremediation")
        if args.get("asmremediation")
        else {
            "Action": "n/a",
            "ActionTimestamp": "n/a",
            "Outcome": "n/a",
            "OutcomeTimestamp": "n/a",
        },
        "asmservicedetection": args.get("asmservicedetection")
        if args.get("asmservicedetection")
        else {
            "ScanDone": "n/a",
            "ScanNum": "n/a",
            "ScanResult": "n/a",
            "ScanState": "n/a",
            "Timestamp": "n/a",
        },
        "asmsystemids": args.get("asmsystemids")
        if args.get("asmsystemids")
        else {
            "ID": "n/a",
            "Link": "n/a",
            "Type": "n/a",
        },
        "asmtags": args.get("asmtags")
        if args.get("asmtags")
        else {"Key": "n/a", "Value": "n/a", "Source": "n/a"},
        "asmrelated": args.get("asmrelated")
        if args.get("asmrelated")
        else {"Type": "n/a", "Link": "n/a"},
    }

    for arg in asm_args:
        # Force all ASM args to List types
        if not isinstance(asm_args[arg], list):
            asm_args.update({arg: [asm_args.get(arg)]})

    return asm_args


""" MAIN FUNCTION """


def main():

    try:
        template = build_template(demisto.args())
        return_results(build_report(template))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute Generate Summary Report. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
