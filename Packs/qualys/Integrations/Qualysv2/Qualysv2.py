import copy
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Callable
from typing import Any
import csv
import io
import requests

from urllib3 import disable_warnings


disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

VENDOR = "qualys"
PRODUCT = "qualys"
BEGIN_RESPONSE_LOGS_CSV = "----BEGIN_RESPONSE_BODY_CSV"
END_RESPONSE_LOGS_CSV = "----END_RESPONSE_BODY_CSV"
BEGIN_RESPONSE_FOOTER_CSV = "----BEGIN_RESPONSE_FOOTER_CSV"
END_RESPONSE_FOOTER_CSV = "----END_RESPONSE_FOOTER_CSV"
WARNING = "WARNING"
ACTIVITY_LOGS_NEWEST_EVENT_DATETIME = "activity_logs_newest_event_datetime"
ACTIVITY_LOGS_NEXT_PAGE = "activity_logs_next_page"
ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN = "activity_logs_since_datetime_prev_run"
HOST_DETECTIONS_NEWEST_EVENT_DATETIME = "host_detections_newest_event_datetime"
HOST_DETECTIONS_NEXT_PAGE = "host_detections_next_page"
HOST_DETECTIONS_SINCE_DATETIME_PREV_RUN = "host_detections_since_datetime_prev_run"
HOST_LAST_FETCH = "host_last_fetch"
ASSETS_FETCH_FROM = "90 days"
HOST_LIMIT = 1000
ASSET_SIZE_LIMIT = 10**6  # 1MB
TEST_FROM_DATE = "one day"
FETCH_ASSETS_COMMAND_TIME_OUT = 180
QIDS_BATCH_SIZE = 500


ASSETS_DATE_FORMAT = "%Y-%m-%d"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
EXECUTION_START_TIME = time.time()
API_SUFFIX = "/api/2.0/fo/"
TAG_API_SUFFIX = "/qps/rest/2.0/"

FETCH_COMMAND = {"events": 0, "assets": 1}
DEFAULT_LAST_ASSETS_RUN = {
    "stage": "assets",
    "next_page": "",
    "total_assets": 0,
    "nextTrigger": None,
    "type": FETCH_COMMAND.get("assets"),
}

# Arguments that need to be parsed as dates
DATE_ARGUMENTS = {
    "launched_after_datetime": "%Y-%m-%d",
    "launched_before_datetime": "%Y-%m-%d",
    "expires_before_datetime": "%Y-%m-%d",
    "no_vm_scan_since": "%Y-%m-%d",
    "vm_scan_since": "%Y-%m-%d",
    "no_compliance_scan_since": "%Y-%m-%d",
    "last_modified_after": "%Y-%m-%d",
    "last_modified_before": "%Y-%m-%d",
    "last_modified_by_user_after": "%Y-%m-%d",
    "last_modified_by_user_before": "%Y-%m-%d",
    "last_modified_by_service_after": "%Y-%m-%d",
    "last_modified_by_service_before": "%Y-%m-%d",
    "published_after": "%Y-%m-%d",
    "published_before": "%Y-%m-%d",
    "start_date": "%m/%d/%Y",
}

# Data for parsing and creating output
COMMANDS_PARSE_AND_OUTPUT_DATA: dict[str, dict[Any, Any]] = {
    "qualys-purge-scan-host-data": {
        "table_name": "Deleted report",
        "json_path": ["BATCH_RETURN", "RESPONSE", "BATCH_LIST", "BATCH"],
        "table_headers": ["ID"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-report-list": {
        "collection_name": "REPORT_LIST",
        "table_name": "Report List",
        "table_headers": [
            "ID",
            "TITLE",
            "TYPE",
            "STATUS",
            "OUTPUT_FORMAT",
            "LAUNCH_DATETIME",
            "EXPIRATION_DATETIME",
            "SIZE",
            "USER_LOGIN",
        ],
        "json_path": ["REPORT_LIST_OUTPUT", "RESPONSE"],
    },
    "qualys-ip-list": {
        "collection_name": "IP_SET",
        "table_names": ["Range List", "Address List"],
        "json_path": ["IP_LIST_OUTPUT", "RESPONSE"],
        "new_names_dict": {"IP": "Address", "IP_RANGE": "Range"},
    },
    "qualys-vm-scan-list": {
        "collection_name": "SCAN_LIST",
        "table_name": "Scan List",
        "table_headers": [
            "REF",
            "TITLE",
            "STATUS",
            "PROCESSED",
            "TYPE",
            "TARGET",
            "PROCESSING_PRIORITY",
            "LAUNCH_DATETIME",
            "DURATION",
            "USER_LOGIN",
        ],
        "json_path": ["SCAN_LIST_OUTPUT", "RESPONSE"],
    },
    "qualys-scap-scan-list": {
        "collection_name": "SCAN_LIST",
        "table_name": "Scap Scan List",
        "json_path": ["SCAN_LIST_OUTPUT", "RESPONSE"],
    },
    "qualys-pc-scan-list": {
        "collection_name": "SCAN_LIST",
        "table_name": "PC Scan List",
        "json_path": ["SCAN_LIST_OUTPUT", "RESPONSE"],
    },
    "qualys-schedule-scan-list": {
        "collection_name": "SCHEDULE_SCAN_LIST",
        "table_name": "Schedule Scan List",
        "json_path": ["SCHEDULE_SCAN_LIST_OUTPUT", "RESPONSE"],
    },
    "qualys-ip-restricted-list": {
        "collection_name": "IP_SET",
        "table_names": ["Range List", "Address List"],
        "json_path": ["RESTRICTED_IPS_OUTPUT", "RESPONSE"],
        "new_names_dict": {"IP": "Address", "IP_RANGE": "Range"},
    },
    "qualys-ip-restricted-manage": {
        "collection_name": "",
        "table_name": "Restricted IPs",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
    },
    "qualys-host-list": {
        "collection_name": "HOST_LIST",
        "table_name": "Host List",
        "json_path": ["HOST_LIST_OUTPUT", "RESPONSE"],
    },
    "qualys-virtual-host-list": {
        "collection_name": "VIRTUAL_HOST_LIST",
        "table_name": "Virtual Host List",
        "json_path": ["VIRTUAL_HOST_LIST_OUTPUT", "RESPONSE"],
    },
    "qualys-host-excluded-list": {
        "collection_name": "IP_SET",
        "table_names": ["Range List", "Address List"],
        "json_path": ["IP_LIST_OUTPUT", "RESPONSE"],
        "new_names_dict": {"IP": "Address", "IP_RANGE": "Range"},
    },
    "qualys-scheduled-report-list": {
        "collection_name": "SCHEDULE_REPORT_LIST",
        "table_name": "Scheduled Report List",
        "json_path": ["SCHEDULE_REPORT_LIST_OUTPUT", "RESPONSE"],
    },
    "qualys-report-template-list": {
        "collection_name": "REPORT_TEMPLATE",
        "table_name": "Template Report List",
        "json_path": ["REPORT_TEMPLATE_LIST", "REPORT_TEMPLATE"],
    },
    "qualys-vulnerability-list": {
        "collection_name": "VULN_LIST",
        "table_name": "Scheduled Report List",
        "json_path": ["KNOWLEDGE_BASE_VULN_LIST_OUTPUT", "RESPONSE"],
    },
    "qualys-group-list": {
        "collection_name": "ASSET_GROUP_LIST",
        "table_name": "Group List",
        "json_path": ["ASSET_GROUP_LIST_OUTPUT", "RESPONSE"],
        "table_headers": ["APPLIANCE_IDS", "DEFAULT_APPLIANCE_ID", "ID", "IP_SET", "TITLE"],
    },
    "qualys-report-fetch": {"file_prefix": "report", "file_id": "id"},
    "qualys-vm-scan-fetch": {
        "table_name": "VM Scan Fetch",
        "json_path": [],
        "file_prefix": "vm_scan",
        "file_id": "scan_ref",
        "new_names_dict": {
            "dns": "Dns",
            "instance": "Instance",
            "ip": "IP",
            "netbios": "Netbios",
            "qid": "QID",
            "result": "Result",
        },
    },
    "qualys-pc-scan-fetch": {
        "table_name": "Policy Compliance Scan",
        "json_path": ["COMPLIANCE_SCAN_RESULT_OUTPUT", "RESPONSE", "COMPLIANCE_SCAN", "HEADER", "KEY"],
    },
    "qualys-report-cancel": {
        "table_name": "Canceled report",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-report-delete": {
        "table_name": "Deleted report",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "table_headers": ["Deleted", "ID"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-scorecard-launch": {
        "table_name": "New scorecard launched",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-vm-scan-launch": {
        "collection_name": "ITEM_LIST",
        "table_name": "New Vulnerability Scan launched",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
    },
    "qualys-vm-scan-action": {
        "json_path": ["SIMPLE_RETURN", "RESPONSE", "ITEM_LIST", "ITEM"],
        "output_texts": {
            "delete": "Deleting scan",
            "pause": "Pausing scan",
            "resume": "Resuming scan",
            "cancel": "Canceling scan",
        },
    },
    "qualys-pc-scan-launch": {
        "collection_name": "ITEM_LIST",
        "table_name": "New PC Scan launched",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
    },
    "qualys-pc-scan-manage": {
        "table_name": "PC Scan",
        "json_path": ["SIMPLE_RETURN", "RESPONSE", "ITEM_LIST", "ITEM"],
    },
    "qualys-ip-add": {
        "table_name": "IP Added",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
    },
    "qualys-ip-update": {
        "table_name": "IP updated",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
    },
    "qualys-host-excluded-manage": {
        "table_name": "Manage Excluded Hosts",
        "json_path": ["SIMPLE_RETURN", "RESPONSE", "ITEM_LIST", "ITEM"],
    },
    "qualys-scheduled-report-launch": {
        "table_name": "Launch Scheduled Report",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-report-launch-map": {
        "table_name": " New report launched",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-report-launch-scan-based-findings": {
        "table_name": "Scan Based Findings Report Launch",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-report-launch-host-based-findings": {
        "table_name": "Host Based Findings Report Launch",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-report-launch-patch": {
        "table_name": "Patch Report Launch",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-report-launch-remediation": {
        "table_name": "Remediation Report Launch",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-report-launch-compliance": {
        "table_name": "Compliance Report Launch",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-report-launch-compliance-policy": {
        "table_name": "Policy Report Launch",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-virtual-host-manage": {
        "table_name": "",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
    },
    "qualys-host-list-detection": {
        "json_path": ["HOST_LIST_VM_DETECTION_OUTPUT", "RESPONSE"],
        "collection_name": "HOST_LIST",
    },
    "qualys-host-update": {
        "table_name": "Host updated",
        "json_path": ["HOST_UPDATE_OUTPUT", "RESPONSE"],
    },
    "qualys-update-unix-record": {
        "table_name": "Update Unix Record",
        "json_path": ["BATCH_RETURN", "RESPONSE", "BATCH_LIST", "BATCH"],
    },
    "qualys-asset-group-add": {
        "table_name": "Asset Group Add",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-asset-group-delete": {
        "table_name": "Asset Group Delete",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-asset-group-edit": {
        "table_name": "Asset Group Edit",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-schedule-scan-create": {
        "table_name": "Schedule Scan Create",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-schedule-scan-update": {
        "table_name": "Schedule Scan Update",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-schedule-scan-delete": {
        "table_name": "Schedule Scan Delete",
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
        "collection_name": "ITEM_LIST",
    },
    "qualys-time-zone-code": {
        "table_name": "Time Zone Codes",
        "json_path": ["TIME_ZONES"],
    },
    "qualys-asset-tag-list": {
        "table_name": "Tags identified by the specified filter",
        "json_path": ["ServiceResponse", "data", "Tag"],
        "table_headers": ["id", "name", "criticalityScore", "ruleType", "ruleText", "childTags"],
    },
    "qualys-asset-tag-create": {
        "table_name": "Asset Tags Created",
        "json_path": ["ServiceResponse", "data", "Tag"],
        "table_headers": ["id", "name", "criticalityScore", "ruleType", "ruleText", "childTags"],
    },
    "qualys-asset-tag-update": {
        "human_readable_massage": "Asset tag updated.",
        "json_path": ["ServiceResponse", "data", "Tag"],
    },
    "qualys-asset-tag-delete": {
        "human_readable_massage": "Asset tag deleted.",
        "json_path": ["ServiceResponse", "data", "Tag"],
    },
    "qualys-update-vmware-record": {
        "json_path": ["BATCH_RETURN", "RESPONSE", "BATCH_LIST", "BATCH"],
    },
    "qualys-update-vcenter-record": {
        "json_path": ["BATCH_RETURN", "RESPONSE", "BATCH_LIST", "BATCH"],
    },
    "qualys-vcenter-esxi-mapped-record-list": {
        "collection_name": "VCENTER_ESXI_MAP",
        "table_name": "Vcenter ESXI IP List",
        "json_path": ["VCENTER_ESXI_MAP_LIST_OUTPUT", "RESPONSE", "VCENTER_ESXI_MAP_LIST", "VCENTER_ESXI_MAP"],
    },
    "qualys-vcenter-esxi-mapped-record-import": {
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
    },
    "qualys-vcenter-esxi-mapped-record-purge": {
        "json_path": ["SIMPLE_RETURN", "RESPONSE"],
    },
}

# Context prefix and key for each command
COMMANDS_CONTEXT_DATA = {
    "qualys-purge-scan-host-data": {"context_prefix": "Qualys.Purge", "context_key": "ID"},
    "qualys-report-list": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-ip-list": {
        "context_prefix": "Qualys.IP",
        "context_key": "IP",
    },
    "qualys-vm-scan-list": {
        "context_prefix": "Qualys.Scan",
        "context_key": "REF",
    },
    "qualys-scap-scan-list": {
        "context_prefix": "Qualys.SCAP.Scan",
        "context_key": "ID",
    },
    "qualys-pc-scan-list": {
        "context_prefix": "Qualys.Scan",
        "context_key": "ID",
    },
    "qualys-schedule-scan-list": {
        "context_prefix": "Qualys.Scan",
        "context_key": "ID",
    },
    "qualys-ip-restricted-list": {
        "context_prefix": "Qualys.Restricted",
        "context_key": "DATETIME",
    },
    "qualys-ip-restricted-manage": {
        "context_prefix": "Qualys.Restricted.Manage",
        "context_key": "DATETIME",
    },
    "qualys-host-list": {
        "context_prefix": "Qualys.Endpoint",
        "context_key": "ID",
    },
    "qualys-virtual-host-list": {
        "context_prefix": "Qualys.VirtualEndpoint",
        "context_key": "IP",
    },
    "qualys-host-excluded-list": {
        "context_prefix": "Qualys.Excluded.Host",
        "context_key": "Host",
    },
    "qualys-scheduled-report-list": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-report-template-list": {
        "context_prefix": "Qualys.ReportTemplate",
        "context_key": "ID",
    },
    "qualys-vulnerability-list": {
        "context_prefix": "Qualys.Vulnerability.List",
        "context_key": "QID",
    },
    "qualys-group-list": {
        "context_prefix": "Qualys.AssetGroup",
        "context_key": "ID",
    },
    "qualys-vm-scan-fetch": {
        "context_prefix": "Qualys.VM",
        "context_key": "QID",
    },
    "qualys-pc-scan-fetch": {"context_prefix": "Qualys.PC", "context_key": "TITLE"},
    "qualys-report-cancel": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-report-delete": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-scorecard-launch": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-vm-scan-launch": {
        "context_prefix": "Qualys.Report.VM.Launched",
        "context_key": "KEY",
    },
    "qualys-vm-scan-action": {
        "context_prefix": "",
        "context_key": "ID",
    },
    "qualys-pc-scan-launch": {
        "context_prefix": "Qualys.Scan",
        "context_key": "ID",
    },
    "qualys-pc-scan-manage": {
        "context_prefix": "Qualys.Scan",
        "context_key": "scan_ref",
    },
    "qualys-ip-add": {
        "context_prefix": "Qualys.IP.Add",
        "context_key": "IP",
    },
    "qualys-ip-update": {
        "context_prefix": "Qualys.IP.Update",
        "context_key": "IP",
    },
    "qualys-host-excluded-manage": {
        "context_prefix": "Qualys.Endpoint",
        "context_key": "KEY",
    },
    "qualys-scheduled-report-launch": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-report-launch-map": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-report-launch-scan-based-findings": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-report-launch-host-based-findings": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-report-launch-patch": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-report-launch-remediation": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-report-launch-compliance": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-report-launch-compliance-policy": {
        "context_prefix": "Qualys.Report",
        "context_key": "ID",
    },
    "qualys-virtual-host-manage": {
        "context_prefix": "Qualys.VirtualEndpoint",
        "context_key": "DATETIME",
    },
    "qualys-host-list-detection": {
        "context_prefix": "Qualys.HostDetections",
        "context_key": "ID",
    },
    "qualys-host-update": {
        "context_prefix": "Qualys.Endpoint.Update",
        "context_key": "ID",
    },
    "qualys-update-unix-record": {
        "context_prefix": "Qualys.UnixRecord",
        "context_key": "ID",
    },
    "qualys-asset-group-add": {
        "context_prefix": "Qualys.AssetGroup",
        "context_key": "ID",
    },
    "qualys-asset-group-edit": {
        "context_prefix": "Qualys.AssetGroup",
        "context_key": "ID",
    },
    "qualys-asset-group-delete": {"context_prefix": "Qualys.AssetGroup", "context_key": "ID"},
    "qualys-schedule-scan-create": {
        "context_prefix": "Qualys.ScheduleScan",
        "context_key": "ID",
    },
    "qualys-schedule-scan-update": {
        "context_prefix": "Qualys.ScheduleScan",
        "context_key": "ID",
    },
    "qualys-schedule-scan-delete": {
        "context_prefix": "Qualys.ScheduleScan",
        "context_key": "ID",
    },
    "qualys-time-zone-code": {
        "context_prefix": "Qualys.TimeZone",
        "context_key": "TIME_ZONE_CODE",
    },
    "qualys-asset-tag-list": {
        "context_prefix": "Qualys.AssetTags",
        "context_key": "AssetTags",
    },
    "qualys-asset-tag-create": {
        "context_prefix": "Qualys.AssetTags",
        "context_key": "AssetTags",
    },
    "qualys-asset-tag-update": {
        "context_prefix": "",
        "context_key": "",
    },
    "qualys-asset-tag-delete": {
        "context_prefix": "",
        "context_key": "",
    },
    "qualys-update-vmware-record": {
        "context_prefix": "",
        "context_key": "",
    },
    "qualys-update-vcenter-record": {
        "context_prefix": "",
        "context_key": "",
    },
    "qualys-vcenter-esxi-mapped-record-list": {
        "context_prefix": "Qualys.VcenterToEsxi",
        "context_key": "VCENTER_IP",
    },
    "qualys-vcenter-esxi-mapped-record-import": {
        "context_prefix": "",
        "context_key": "",
    },
    "qualys-vcenter-esxi-mapped-record-purge": {
        "context_prefix": "",
        "context_key": "",
    },
}

# Information about the API request of the commands
COMMANDS_API_DATA: dict[str, dict[str, str]] = {
    "qualys-purge-scan-host-data": {
        "api_route": API_SUFFIX + "asset/host/?action=purge",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-list": {
        "api_route": API_SUFFIX + "/report/?action=list",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-ip-list": {
        "api_route": API_SUFFIX + "/asset/ip/?action=list",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-vm-scan-list": {
        "api_route": API_SUFFIX + "/scan/?action=list",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-scap-scan-list": {
        "api_route": API_SUFFIX + "/scan/scap/?action=list",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-pc-scan-list": {
        "api_route": API_SUFFIX + "/scan/compliance/?action=list",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-schedule-scan-list": {
        "api_route": API_SUFFIX + "/schedule/scan/?action=list",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-ip-restricted-list": {
        "api_route": API_SUFFIX + "/setup/restricted_ips/?action=list&output_format=xml",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-ip-restricted-manage": {
        "api_route": API_SUFFIX + "/setup/restricted_ips/",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-host-list": {
        "api_route": API_SUFFIX + "/asset/host/?action=list",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-virtual-host-list": {
        "api_route": API_SUFFIX + "/asset/vhost/?action=list",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-host-excluded-list": {
        "api_route": API_SUFFIX + "/asset/excluded_ip/?action=list",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-scheduled-report-list": {
        "api_route": API_SUFFIX + "/schedule/report/?action=list",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-report-template-list": {
        "api_route": "/msp/report_template_list.php",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-vulnerability-list": {
        "api_route": API_SUFFIX + "/knowledge_base/vuln/?action=list",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-group-list": {
        "api_route": API_SUFFIX + "/asset/group/?action=list",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-fetch": {
        "api_route": API_SUFFIX + "/report/?action=fetch",
        "call_method": "POST",
        "resp_type": "content",
    },
    "qualys-vm-scan-fetch": {
        "api_route": API_SUFFIX + "scan/?action=fetch&output_format=json",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-pc-scan-fetch": {
        "api_route": API_SUFFIX + "scan/compliance/?action=fetch",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-report-cancel": {
        "api_route": API_SUFFIX + "report/?action=cancel",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-delete": {
        "api_route": API_SUFFIX + "report/?action=delete",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-scorecard-launch": {
        "api_route": API_SUFFIX + "/report/scorecard/?action=launch",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-vm-scan-launch": {
        "api_route": API_SUFFIX + "/scan/?action=launch",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-vm-scan-action": {
        "api_route": API_SUFFIX + "/scan/",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-pc-scan-launch": {
        "api_route": API_SUFFIX + "/scan/compliance/?action=launch",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-pc-scan-manage": {
        "api_route": API_SUFFIX + "/scan/compliance/?action=launch",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-ip-add": {
        "api_route": API_SUFFIX + "/asset/ip/?action=add",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-ip-update": {
        "api_route": API_SUFFIX + "/asset/ip/?action=update",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-host-excluded-manage": {
        "api_route": API_SUFFIX + "/asset/excluded_ip/",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-scheduled-report-launch": {
        "api_route": API_SUFFIX + "/schedule/report/?action=launch_now",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-launch-map": {
        "api_route": API_SUFFIX + "/report/?action=launch&report_type=Map",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-launch-scan-based-findings": {
        "api_route": API_SUFFIX + "/report/?action=launch&report_type=Scan",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-launch-host-based-findings": {
        "api_route": API_SUFFIX + "/report/?action=launch&report_type=Scan",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-launch-patch": {
        "api_route": API_SUFFIX + "/report/?action=launch&report_type=Patch",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-launch-remediation": {
        "api_route": API_SUFFIX + "/report/?action=launch&report_type=Remediation",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-launch-compliance": {
        "api_route": API_SUFFIX + "report/?action=launch&report_type=Compliance",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-report-launch-compliance-policy": {
        "api_route": API_SUFFIX + "/report/?action=launch&report_type=Policy",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-virtual-host-manage": {
        "api_route": API_SUFFIX + "asset/vhost/",
        "call_method": "POST",
        "resp_type": "text",
    },
    "test-module": {
        "api_route": API_SUFFIX + "/scan/?action=list",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-host-list-detection": {
        # show detection score `QDS` and score contributing factors `QDS_FACTORS`
        "api_route": API_SUFFIX + "asset/host/vm/detection/?action=list&show_qds=1&show_qds_factors=1",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-host-update": {
        "api_route": API_SUFFIX + "asset/host/?action=update",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-update-unix-record": {
        "api_route": API_SUFFIX + "auth/unix/?action=update",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-asset-group-add": {
        "api_route": API_SUFFIX + "asset/group/?action=add",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-asset-group-edit": {
        "api_route": API_SUFFIX + "asset/group/?action=edit",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-asset-group-delete": {
        "api_route": API_SUFFIX + "asset/group/?action=delete",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-schedule-scan-create": {
        "api_route": API_SUFFIX + "schedule/scan/?action=create&active=1",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-schedule-scan-update": {
        "api_route": API_SUFFIX + "schedule/scan/?action=update",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-schedule-scan-delete": {
        "api_route": API_SUFFIX + "schedule/scan/?action=delete",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-time-zone-code": {
        "api_route": "/msp/time_zone_code_list.php",
        "call_method": "GET",
        "resp_type": "text",
    },
    "qualys-update-vmware-record": {
        "api_route": API_SUFFIX + "auth/vmware/?action=update",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-update-vcenter-record": {
        "api_route": API_SUFFIX + "auth/vcenter/?action=update",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-vcenter-esxi-mapped-record-list": {
        "api_route": API_SUFFIX + "auth/vcenter/vcenter_mapping/?action=list&output_format=xml",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-vcenter-esxi-mapped-record-import": {
        "api_route": API_SUFFIX + "auth/vcenter/vcenter_mapping/?action=import",
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-vcenter-esxi-mapped-record-purge": {
        "api_route": API_SUFFIX + "auth/vcenter/vcenter_mapping/?action=purge",
        "call_method": "POST",
        "resp_type": "text",
    },
}

# Information about the API tag asset request of the commands
TAG_ASSET_COMMANDS_API_DATA: dict[str, dict[str, Any]] = {
    "qualys-asset-tag-create": {
        "api_route": urljoin(TAG_API_SUFFIX, "create/am/tag"),
        "call_method": "POST",
        "resp_type": "text",
        "request_body": {"ServiceRequest": {}},
        "Content-Type": "text/xml",
    },
    "qualys-asset-tag-update": {
        "api_route": urljoin(TAG_API_SUFFIX, "update/am/tag"),
        "call_method": "POST",
        "resp_type": "text",
        "request_body": {"ServiceRequest": {}},
        "Content-Type": "text/xml",
    },
    "qualys-asset-tag-delete": {
        "api_route": urljoin(TAG_API_SUFFIX, "delete/am/tag"),
        "call_method": "POST",
        "resp_type": "text",
    },
    "qualys-asset-tag-list": {
        "api_route": urljoin(TAG_API_SUFFIX, "search/am/tag"),
        "call_method": "POST",
        "resp_type": "text",
        "request_body": {"ServiceRequest": {}},
        "Content-Type": "text/xml",
    },
}

# Arguments' names of each command
COMMANDS_ARGS_DATA: dict[str, Any] = {
    "qualys-purge-scan-host-data": {
        "args": [
            "action",
            "echo_request",
            "ids",
            "ips",
            "ag_ids",
            "ag_titles",
            "network_ids",
            "no_vm_scan_since",
            "no_compliance_scan_since",
            "data_scope",
            "compliance_enabled",
            "os_pattern",
        ]
    },
    "qualys-report-list": {
        "args": ["id", "state", "user_login", "expires_before_datetime", "client_id", "client_name"],
        "inner_args": ["limit"],
    },
    "qualys-ip-list": {
        "args": ["ips", "network_id", "tracking_method", "compliance_enabled"],
        "inner_args": ["limit"],
    },
    "qualys-vm-scan-list": {
        "args": [
            "scan_ref",
            "state",
            "processed",
            "type",
            "target",
            "user_login",
            "launched_after_datetime",
            "launched_before_datetime",
            "show_ags",
            "show_op",
            "show_status",
            "show_last",
            "scan_id",
            "client_id",
            "client_name",
            "pci_only",
            "ignore_target",
        ],
        "inner_args": ["limit"],
    },
    "qualys-scap-scan-list": {
        "args": [
            "scan_ref",
            "state",
            "processed",
            "type",
            "target",
            "user_login",
            "launched_after_datetime",
            "launched_before_datetime",
            "show_ags",
            "show_op",
            "show_status",
            "show_last",
            "scan_id",
            "client_id",
            "client_name",
            "pci_only",
            "ignore_target",
        ],
        "inner_args": ["limit"],
    },
    "qualys-pc-scan-list": {
        "args": [
            "scan_id",
            "scan_ref",
            "state",
            "processed",
            "type",
            "target",
            "user_login",
            "launched_after_datetime",
            "launched_before_datetime",
            "show_ags",
            "show_op",
            "show_status",
            "show_last",
            "client_id",
            "client_name",
            "pci_only",
            "ignore_target",
        ],
        "inner_args": ["limit"],
    },
    "qualys-schedule-scan-list": {
        "args": [
            "id",
            "active",
            "show_notifications",
            "scan_type",
            "fqdn",
            "show_cloud_details",
            "client_id",
            "client_name",
            "show_cloud_details",
        ],
        "inner_args": ["limit"],
    },
    "qualys-ip-restricted-list": {
        "args": [],
        "inner_args": ["limit"],
    },
    "qualys-ip-restricted-manage": {
        "args": ["action", "enable", "ips"],
    },
    "qualys-host-list": {
        "args": [
            "os_pattern",
            "truncation_limit",
            "ips",
            "ag_titles",
            "ids",
            "network_ids",
            "no_vm_scan_since",
            "vm_scan_since",
            "no_compliance_scan_since",
            "use_tags",
            "tag_set_by",
            "tag_include_selector",
            "tag_exclude_selector",
            "tag_set_include",
            "tag_set_exclude",
            "show_tags",
            "host_metadata",
            "host_metadata_fields",
            "show_cloud_tags",
            "cloud_tag_fields",
            "details",
        ],
        "inner_args": ["limit"],
    },
    "qualys-virtual-host-list": {
        "args": ["port", "ip"],
        "inner_args": ["limit"],
    },
    "qualys-host-excluded-list": {
        "args": [
            "ips",
            "network_id",
            "ag_ids",
            "ag_titles",
            "use_tags",
            "tag_include_selector",
            "tag_exclude_selector",
            "tag_set_by",
            "tag_set_include",
            "tag_set_exclude",
        ],
        "inner_args": ["limit"],
    },
    "qualys-scheduled-report-list": {
        "args": ["id", "is_active"],
        "inner_args": ["limit"],
    },
    "qualys-report-template-list": {
        "args": [],
        "inner_args": ["limit"],
    },
    "qualys-vulnerability-list": {
        "args": [
            "details",
            "ids",
            "id_min",
            "id_max",
            "is_patchable",
            "last_modified_after",
            "last_modified_before",
            "last_modified_by_user_after",
            "last_modified_by_user_before",
            "last_modified_by_service_after",
            "last_modified_by_service_before",
            "published_after",
            "published_before",
            "discovery_method",
            "discovery_auth_types",
            "show_pci_reasons",
            "show_supported_modules_info",
            "show_disabled_flag",
            "show_qid_change_log",
        ],
        "inner_args": ["limit"],
    },
    "qualys-group-list": {
        "args": ["ids", "id_min", "id_max", "truncation_limit", "network_ids", "unit_id", "user_id", "title", "show_attributes"],
        "inner_args": ["limit"],
    },
    "qualys-report-fetch": {
        "args": ["id"],
        "inner_args": ["file_format"],
    },
    "qualys-vm-scan-fetch": {
        "args": ["scan_ref", "ips", "mode", "client_id", "client_name"],
    },
    "qualys-pc-scan-fetch": {
        "args": ["scan_ref"],
    },
    "qualys-report-cancel": {
        "args": ["id"],
    },
    "qualys-report-delete": {
        "args": ["id"],
    },
    "qualys-scorecard-launch": {
        "args": [
            "name",
            "report_title",
            "output_format",
            "hide_header",
            "pdf_password",
            "recipient_group",
            "recipient_group_id",
            "source",
            "asset_groups",
            "all_asset_groups",
            "business_unit",
            "division",
            "function",
            "location",
            "patch_qids",
            "missing_qids",
        ],
    },
    "qualys-vm-scan-launch": {
        "args": [
            "scan_title",
            "target_from",
            "ip",
            "asset_groups",
            "asset_group_ids",
            "exclude_ip_per_scan",
            "tag_include_selector",
            "tag_exclude_selector",
            "tag_set_by",
            "tag_set_include",
            "tag_set_exclude",
            "use_ip_nt_range_tags_include",
            "use_ip_nt_range_tags_exclude",
            "use_ip_nt_range_tags",
            "iscanner_id",
            "iscanner_name",
            "default_scanner",
            "scanners_in_ag",
            "scanners_in_tagset",
            "scanners_in_network",
            "option_title",
            "option_id",
            "priority",
            "connector_name",
            "ec2_endpoint",
            "ec2_instance_ids",
            "ip_network_id",
            "runtime_http_header",
            "scan_type",
            "fqdn",
            "client_id",
            "client_name",
            "include_agent_targets",
        ],
        "required_groups": [
            ["option_id", "option_title"],
        ],
    },
    "qualys-vm-scan-action": {
        "args": ["action", "scan_ref"],
    },
    "qualys-pc-scan-launch": {
        "args": [
            "scan_title",
            "option_id",
            "option_title",
            "ip",
            "asset_group_ids",
            "asset_groups",
            "runtime_http_header",
            "exclude_ip_per_scan",
            "default_scanner",
            "scanners_in_ag",
            "target_from",
            "tag_include_selector",
            "tag_exclude_selector",
            "tag_set_by",
            "tag_set_include",
            "tag_set_exclude",
            "use_ip_nt_range_tags",
            "ip_network_id",
            "iscanner_name",
        ],
        "required_groups": [
            ["option_id", "option_title"],
        ],
    },
    "qualys-pc-scan-manage": {
        "args": ["action", "scan_ref"],
    },
    "qualys-ip-add": {
        "args": ["ips", "tracking_method", "enable_vm", "enable_pc", "owner", "ud1", "ud2", "ud3", "comment", "ag_title"],
    },
    "qualys-ip-update": {
        "args": ["ips", "network_id", "tracking_method", "host_dns", "host_netbios", "owner", "ud1", "ud2", "ud3", "comment"],
    },
    "qualys-host-excluded-manage": {
        "args": ["action", "ips", "expiry_days", "dg_names", "comment", "network_id"],
    },
    "qualys-scheduled-report-launch": {
        "args": ["id"],
    },
    "qualys-report-launch-map": {
        "args": [
            "domain",
            "ip_restriction",
            "report_refs",
            "template_id",
            "report_title",
            "output_format",
            "hide_header",
            "pdf_password",
            "recipient_group",
            "recipient_group_id",
        ],
    },
    "qualys-report-launch-scan-based-findings": {
        "args": [
            "template_id",
            "report_title",
            "output_format",
            "hide_header",
            "recipient_group_id",
            "pdf_password",
            "recipient_group",
            "ip_restriction",
            "report_refs",
        ],
    },
    "qualys-report-launch-host-based-findings": {
        "args": [
            "template_id",
            "report_title",
            "output_format",
            "hide_header",
            "recipient_group_id",
            "pdf_password",
            "recipient_group",
            "ips",
            "asset_group_ids",
            "ips_network_id",
        ],
    },
    "qualys-report-launch-patch": {
        "args": [
            "template_id",
            "report_title",
            "output_format",
            "hide_header",
            "recipient_group_id",
            "pdf_password",
            "recipient_group",
            "ips",
            "asset_group_ids",
        ],
    },
    "qualys-report-launch-remediation": {
        "args": [
            "template_id",
            "report_title",
            "output_format",
            "hide_header",
            "recipient_group_id",
            "pdf_password",
            "recipient_group",
            "ips",
            "asset_group_ids",
            "asignee_type",
        ],
    },
    "qualys-report-launch-compliance": {
        "args": [
            "template_id",
            "report_title",
            "output_format",
            "hide_header",
            "recipient_group_id",
            "pdf_password",
            "recipient_group",
            "ips",
            "asset_group_ids",
            "report_refs",
        ],
    },
    "qualys-report-launch-compliance-policy": {
        "args": [
            "template_id",
            "report_title",
            "output_format",
            "hide_header",
            "recipient_group_id",
            "pdf_password",
            "recipient_group",
            "ips",
            "asset_group_ids",
            "policy_id",
            "host_id",
            "instance_string",
        ],
    },
    "qualys-virtual-host-manage": {
        "args": ["action", "ip", "network_id", "port", "fqdn"],
    },
    "test-module": {"args": ["launched_after_datetime"]},
    "qualys-host-list-detection": {
        "args": [
            "ids",
            "ips",
            "qids",
            "severities",
            "use_tags",
            "tag_set_by",
            "tag_include_selector",
            "tag_exclude_selector",
            "tag_set_include",
            "tag_set_exclude",
            "detection_processed_before",
            "detection_processed_after",
            "vm_scan_since",
            "no_vm_scan_since",
            "truncation_limit",
        ]
    },
    "qualys-host-update": {
        "args": [
            "ids",
            "ips",
            "network_id",
            "host_dns",
            "host_netbios",
            "tracking_method",
            "new_tracking_method",
            "new_owner",
            "new_comment",
            "new_ud1",
            "new_ud2",
            "new_ud3",
        ],
        "required_groups": [
            [
                "ids",
                "ips",
            ]
        ],
    },
    "qualys-update-unix-record": {
        "args": ["ids", "add_ips"],
    },
    "qualys-update-vmware-record": {
        "args": ["ids", "add_ips"],
    },
    "qualys-update-vcenter-record": {
        "args": ["ids", "add_ips"],
    },
    "qualys-vcenter-esxi-mapped-record-list": {
        "args": [],
        "inner_args": ["limit"],
    },
    "qualys-vcenter-esxi-mapped-record-import": {
        "args": ["csv_data"],
    },
    "qualys-vcenter-esxi-mapped-record-purge": {
        "args": ["csv_data"],
    },
    "qualys-asset-group-add": {
        "args": [
            "title",
            "network_id",
            "ips",
            "domains",
            "dns_names",
            "netbios_names",
            "cvss_enviro_td",
            "cvss_enviro_cr",
            "cvss_enviro_ir",
            "cvss_enviro_ar",
            "appliance_ids",
        ]
    },
    "qualys-asset-group-edit": {
        "args": [
            "set_title",
            "id",
            "add_ips",
            "set_ips",
            "remove_ips",
            "add_domains",
            "remove_domains",
            "set_domains",
            "add_dns_names",
            "set_dns_names",
            "remove_dns_names",
            "add_netbios_names",
            "set_netbios_names",
            "remove_netbios_names",
            "set_cvss_enviro_td",
            "set_cvss_enviro_cr",
            "set_cvss_enviro_ir",
            "set_cvss_enviro_ar",
            "add_appliance_ids",
            "set_appliance_ids",
            "remove_appliance_ids",
        ]
    },
    "qualys-asset-group-delete": {"args": ["id"]},
    "qualys-schedule-scan-create": {
        "args": [
            "scan_title",
            "asset_group_ids",
            "asset_groups",
            "ip",
            "option_title",
            "frequency_days",
            "weekdays",
            "frequency_weeks",
            "frequency_months",
            "day_of_month",
            "day_of_week",
            "week_of_month",
            "start_date",
            "start_hour",
            "start_minute",
            "time_zone_code",
            "exclude_ip_per_scan",
            "default_scanner",
            "scanners_in_ag",
            "observe_dst",
            "ip_network_id",
            "option_id",
            "end_after",
            "target_from",
            "tag_include_selector",
            "tag_exclude_selector",
            "tag_set_by",
            "tag_set_include",
            "tag_set_exclude",
            "use_ip_nt_range_tags_include",
            "use_ip_nt_range_tags_exclude",
            "active",
            "scanners_in_network",
            "fqdn",
            "recurrence",
            "end_after_mins",
            "iscanner_id",
            "iscanner_name",
        ],
        "required_groups": [
            [
                "asset_group_ids",
                "asset_groups",
                "ip",
                "fqdn",
            ],
            [
                "frequency_days",
                "frequency_weeks",
                "frequency_months",
            ],
            [
                "scanners_in_ag",
                "default_scanner",
            ],
        ],
        "required_depended_args": {
            "day_of_month": "frequency_months",
            "day_of_week": "frequency_months",
            "week_of_month": "frequency_months",
            "weekdays": "frequency_weeks",
        },
        "default_added_depended_args": {
            "frequency_days": {
                "occurrence": "daily",
            },
            "frequency_weeks": {
                "occurrence": "weekly",
            },
            "frequency_months": {
                "occurrence": "monthly",
            },
        },
    },
    "qualys-schedule-scan-update": {
        "args": [
            "id",
            "scan_title",
            "asset_group_ids",
            "asset_groups",
            "ip",
            "frequency_days",
            "weekdays",
            "frequency_weeks",
            "frequency_months",
            "day_of_month",
            "day_of_week",
            "week_of_month",
            "start_date",
            "start_hour",
            "start_minute",
            "time_zone_code",
            "exclude_ip_per_scan",
            "default_scanner",
            "scanners_in_ag",
            "active",
            "observe_dst",
            "target_from",
            "iscanner_name",
            "ip_network_id",
            "option_id",
            "end_after",
            "tag_include_selector",
            "tag_exclude_selector",
            "tag_set_by",
            "tag_set_include",
            "tag_set_exclude",
            "use_ip_nt_range_tags_include",
            "use_ip_nt_range_tags_exclude",
        ],
        "default_added_depended_args": {
            "frequency_days": {
                "occurrence": "daily",
            },
            "frequency_weeks": {
                "occurrence": "weekly",
            },
            "frequency_months": {
                "occurrence": "monthly",
            },
            "start_hour": {
                "set_start_time": 1,
            },
            "start_minute": {
                "set_start_time": 1,
            },
            "start_date": {
                "set_start_time": 1,
            },
            "observe_dst": {
                "set_start_time": 1,
            },
            "time_zone_code": {
                "set_start_time": 1,
            },
        },
        "required_depended_args": {
            "day_of_month": "frequency_months",
            "day_of_week": "frequency_months",
            "week_of_month": "frequency_months",
            "weekdays": "frequency_weeks",
            "start_hour": "start_date",
            "start_minute": "start_date",
            "time_zone_code": "start_date",
            "observe_dst": "start_date",
        },
        "at_most_one_groups": [
            [
                "asset_group_ids",
                "asset_groups",
                "ip",
            ],
            [
                "frequency_days",
                "frequency_weeks",
                "frequency_months",
            ],
            [
                "scanners_in_ag",
                "default_scanner",
            ],
        ],
    },
    "qualys-schedule-scan-delete": {
        "args": [
            "id",
        ]
    },
    "qualys-time-zone-code": {"args": []},
    "qualys-asset-tag-create": {"args": ["name", "child_name", "rule_type", "rule_text", "criticality_score"]},
    "qualys-asset-tag-update": {"args": ["id", "name", "rule_type", "rule_text", "child_to_remove", "criticality_score"]},
    "qualys-asset-tag-delete": {"args": ["id"]},
    "qualys-asset-tag-list": {"args": ["criteria", "operator", "search_data", "limit"]},
}

# Dictionary for arguments used by Qualys API
args_values: dict[str, Any] = {}

# Dictionary for arguments used internally by this integration
inner_args_values: dict[str, Any] = {}

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url, username, password, verify=True, proxy=False, headers=None):
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers, auth=(username, password))

    @staticmethod
    def error_handler(res):
        err_msg = ""
        if res.status_code == 414 or res.status_code == 520:
            err_msg += (
                "If this error was produced by a schedule-scan-create, "
                "please execute it again with IP list of less than 5000 characters\n\n"
            )
        err_msg += f"Error in API call [{res.status_code}] - {res.reason}"
        try:
            simple_response = get_simple_response_from_raw(parse_raw_response(res.text))
            err_msg = f'{err_msg}\nError Code: {simple_response.get("CODE")}\nError Message: {simple_response.get("TEXT")}'
        except Exception:
            try:
                # Try to parse json error response
                error_entry = res.json()
                err_msg += f"\n{json.dumps(error_entry)}"
                raise DemistoException(err_msg, res=res)
            except (ValueError, TypeError):
                err_msg += f"\n{res.text}"
                raise DemistoException(err_msg, res=res)
        raise DemistoException(err_msg, res=res)

    @logger
    def command_http_request(self, command_api_data: dict[str, str]) -> Union[str, bytes]:
        """
        Make a http request to Qualys API
        Args:
            command_api_data: Information about the API request of the requested command
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        if content_type := command_api_data.get("Content-Type"):
            self._headers.update({"Content-Type": content_type})

        return self._http_request(
            method=command_api_data["call_method"],
            url_suffix=command_api_data["api_route"],
            params=args_values,
            resp_type=command_api_data["resp_type"],
            timeout=60,
            data=command_api_data.get("request_body", None),
            error_handler=self.error_handler,
        )

    def get_user_activity_logs(self, since_datetime: str, max_fetch: int = 0, next_page=None) -> Union[str, bytes]:
        """
        Make a http request to Qualys API to get user activities logs
        Args:
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        self._headers.update({"Content-Type": "application/json"})
        params: dict[str, Any] = {"truncation_limit": max_fetch}
        if since_datetime:
            params["since_datetime"] = since_datetime
        if next_page:
            params["id_max"] = next_page

        response = self._http_request(
            method="GET",
            url_suffix=urljoin(API_SUFFIX, "activity_log/?action=list"),
            resp_type="text/csv",
            params=params,
            timeout=60,
            error_handler=self.error_handler,
        )

        return response.text

    def get_host_list_detection(
        self,
        since_datetime: str,
        next_page: str | None = None,
        limit: int = HOST_LIMIT,
    ) -> tuple[Union[str, bytes], bool]:
        """
        Make a http request to Qualys API to get assets
        Args:
            since_datetime (str): Filter hosts by vulnerability scan end date. Specify in the `YYYY-MM-DD[THH:MM:SSZ]` format.
            next_page (str | None): For pagination; show hosts starting from a minimum host ID value.
            limit (int): Maximum number of host records returned; should be <= 1000000. Specify 0 for no truncation limit.
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        set_new_limit = False
        self._headers.update({"Content-Type": "application/json"})
        params: dict[str, Any] = {
            "truncation_limit": limit,
            "vm_scan_date_after": since_datetime,
            "show_qds": 1,  # Show host detection score `QDS` and score contributing factors `QDS_FACTORS`
            "show_qds_factors": 1,
        }
        timeout = (60, 150)  # (Connection Timeout, Read Timeout)
        if next_page:
            params["id_min"] = next_page
        try:
            response = self._http_request(
                method="GET",
                url_suffix=urljoin(API_SUFFIX, "asset/host/vm/detection/?action=list"),
                resp_type="text",
                params=params,
                timeout=timeout,
                error_handler=self.error_handler,
            )
        except requests.exceptions.ReadTimeout:
            demisto.debug("A timeout occurred during the request")
            set_new_limit = True
            response = ""

        return response, set_new_limit

    def get_vulnerabilities(self, since_datetime: str | None = None, detection_qids: str | None = None) -> requests.Response:
        """
        Make a http request to Qualys API to get vulnerabilities
        Args:
            since_datetime (str | None): Optional timestamp for filtering vulnerabilities that have been modified afterwards.
            detection_qids (str | None): Optional string of comma-separated values for filtering by Qualys host detection IDs.
        Returns:
            response from Qualys API
        Raises:
            DemistoException: can be raised by the _http_request function
        """
        self._headers.update({"Content-Type": "application/json"})

        params: dict[str, Any] = assign_params(ids=detection_qids, last_modified_after=since_datetime)

        response = self._http_request(
            method="POST",
            url_suffix=urljoin(API_SUFFIX, "knowledge_base/vuln/?action=list"),
            resp_type="text",
            params=params,
            timeout=60,
            error_handler=self.error_handler,
        )

        return response


""" HELPER FUNCTIONS """


@logger
def create_ip_list_dict(res_json: dict[str, Any], type_of_dict: str) -> dict[str, Any]:
    """
    Creates a dictionary of a range type of ips or single address type of ips
    Args:
        res_json: Dictionary received from ip list command with 'Address' or 'Range' keys
        type_of_dict: The wanted type of dictionary: 'Range' or 'Address'
    Returns:
        A dictionary with the specified type of ips values
    """
    ips_dict = {}

    if type_of_dict in res_json:
        ips = res_json[type_of_dict]
        # In case a single value returned it can be either a Dict or a str
        if isinstance(ips, dict | str):
            ips_dict = {"0": ips}
        else:
            for index, ip in enumerate(ips):
                ips_dict[str(index)] = ip
        return ips_dict
    return {}


@logger
def build_ip_and_range_dicts(ips_and_ranges: List[str]) -> List[List[dict[str, str]]]:
    """
    Separates the list of ips and ranges to two lists, one of singles ips
    and the other of ranges of ips
    Args:
        ips_and_ranges: A list that might contain both ips and ranges of ips
    Returns: A list that has one list which consists of single value dictionaries of ips
             and another list which consists of single values dictionaries of ranges
    """
    list_of_ips = []
    list_of_ranges = []
    for value in ips_and_ranges:
        if "-" in value:
            list_of_ranges.append({"range": value})
        else:
            list_of_ips.append({"ip": value})
    return [list_of_ips, list_of_ranges]


@logger
def create_single_host_list(ip_and_range_lists: dict[str, Union[str, List]]) -> List[str]:
    """
    Creates a single list containing both single ips and ranges of ips
    Args:
        ip_and_range_lists: A dictionary that can have either a single ip as a string or
        a list of single ips in the key 'Address' and/or a single range as a string or
        a list of range of ips in the key 'Range'
    Returns: A list that has both ips and ranges of ips
    """
    ip_and_range_list = []

    if "Address" in ip_and_range_lists:
        if isinstance(ip_and_range_lists["Address"], str):
            ip_and_range_list.extend([ip_and_range_lists["Address"]])
        else:
            for address in ip_and_range_lists["Address"]:
                ip_and_range_list.append(address)
    if "Range" in ip_and_range_lists:
        if isinstance(ip_and_range_lists["Range"], str):
            ip_and_range_list.extend([ip_and_range_lists["Range"]])
        else:
            for ip_range in ip_and_range_lists["Range"]:
                ip_and_range_list.append(ip_range)
    return ip_and_range_list


@logger
def create_ip_list_markdown_table(dicts_of_ranges_and_ips: List[List[dict[str, str]]]) -> str:
    """
    Creates two tables one describes a list of ips and the other a list of ranges
    Args:
        dicts_of_ranges_and_ips: A list which might contain one or two lists of dictionaries. One is a list of Ips
                                 and the other a list of ranges
    Returns: A string which is a markdown representation of the lists
    """
    readable_output = ""
    if dicts_of_ranges_and_ips[0]:
        readable_output += f"{tableToMarkdown(name='', t=dicts_of_ranges_and_ips[0])}\n"
    if dicts_of_ranges_and_ips[1]:
        readable_output += tableToMarkdown(name="", t=dicts_of_ranges_and_ips[1])
    return readable_output


@logger
def create_ip_list_dicts(res_json: dict[str, Any]) -> List[dict[str, Any]]:
    """
    Creates separate dictionaries of addresses and ranges
    Args:
        res_json: Dictionary received from ip list command with 'Address' or 'Range' keys
    Returns:
        List with address dictionary and ranges of addresses dictionary
    Raises:
        DemistoException: dictionary doesn't have any of the expected keys
        TypeError: res_json is not a dictionary
    """
    output_list = []

    address_dict = create_ip_list_dict(res_json, "Address")
    range_dict = create_ip_list_dict(res_json, "Range")
    if address_dict:
        output_list.append(address_dict)
    if range_dict:
        output_list.append(range_dict)

    if not output_list:
        raise DemistoException("IP list command is missing keys")

    return output_list


@logger
def generate_list_dicts(asset_dict: dict[str, Any]) -> Union[List[Any], dict]:
    """
        Takes a dictionary with a specific structure of a single key containing
        a list of dictionaries and returns the list of dictionaries
    Args:
        asset_dict: Dictionary that contains a single asset type returned from the API
    Returns:
        A list of assets of the asset type requested
    """
    return list(asset_dict.values())[0]


@logger
def build_args_dict(args: Optional[dict[str, str]], command_args_data: dict[str, Any], is_inner_args: bool) -> None:
    """
    Takes the arguments needed by the command that were received by the user
    and stores them in the general commands data dictionary
    Args:
        args: Dictionary of arguments received by the user
        command_args_data: names of the arguments used by the command
        is_inner_args: if True - will create dict for inner args otherwise will create dict args for the API
    Returns:
        None
    """
    global inner_args_values, args_values
    if is_inner_args and "inner_args" in command_args_data:
        type_of_args_name = "inner_args"
    else:
        type_of_args_name = "args"

    args_dict = {}
    if args:
        for arg in command_args_data[type_of_args_name]:
            if args.get(arg):
                if arg in DATE_ARGUMENTS:
                    datetime_arg = arg_to_datetime(args.get(arg))
                    if datetime_arg:
                        args[arg] = datetime_arg.strftime(DATE_ARGUMENTS.get(arg, "%Y-%m-%d"))
                args_dict[arg] = args.get(arg)

    # If some args are given, we want to add more args with default value.
    for arg_depending_on, depended_args_dict in command_args_data.get("default_added_depended_args", {}).items():
        if arg_depending_on in args_dict:
            args_dict.update(depended_args_dict)

    if type_of_args_name == "inner_args":
        inner_args_values = args_dict
    else:
        args_values = args_dict


@logger
def is_empty_result(json_response: dict[str, Any]) -> bool:
    """
    Checking whether the response object contains no object or only timestamp object,
    both are considered an empty result, otherwise it's not empty
    Args:
        json_response: Dictionary received by the request to the API

    Returns: True if the dictionary is empty, otherwise return False
    """
    return bool(not json_response or len(json_response) == 1 and json_response.get("DATETIME"))


@logger
def limit_result(result: List[Any], limit: Union[int, str]) -> List[Any]:
    """
    Given the result and a limit amount,  the result will be limited to amount requested
    Args:
        result: A list of results received
        limit: either int or string representing how many entries should be shown
    Returns:
        returns result after applying slicing so only the wanted amount of entries will be shown.
    """
    limit = int(limit)
    limited_list = result[:limit]
    return limited_list


@logger
def calculate_ip_original_amount(result: dict[str, Any]) -> int:
    """
    Calculating the amount of ip addresses and ranges returned.
    Args:
        result: Parsed output, a dictionary that might contain a list of single ips and a list of ranges of ips.
        IP addresses and ranges are represented by a list of items, unless there's only a single item,
        then it's a string.
    Returns: An integer which is the amount of ip addresses and ranges
    """
    original_amount = 0
    if "Address" in result:
        if isinstance(result["Address"], str):
            original_amount += 1
        else:
            original_amount += len(result["Address"])
    if "Range" in result:
        if isinstance(result["Range"], str):
            original_amount += 1
        else:
            original_amount += len(result["Range"])
    return original_amount


@logger
def limit_ip_results(result: dict[str, Any], limit: int) -> dict[str, Any]:
    """
    Limiting the results of commands like qualys-ip-list and qualys-excluded-host-list.
    First will limit the single ips and if needed will also limit the ranges of ips list
    Args:
        result: Parsed output, a dictionary that might contain a list of single ips and a list of ranges of ips
        limit: The limit of the presented list, cannot be smaller than 1
    Returns:
        The given dictionary but after the limit was applied
    """
    if "Address" in result:
        if isinstance(result["Address"], list):
            if len(result["Address"]) > limit:
                result["Address"] = limit_result(result["Address"], limit)
            limit = limit - len(result["Address"])
        else:
            # When there's a single IP it's not a list but a single string, therefore subtract 1 from the limit
            limit -= 1

    if "Range" in result:
        if isinstance(result["Range"], list):
            result["Range"] = limit_result(result["Range"], limit)
        else:
            if limit == 0:
                # When there's a single IP it's not a list but a single string, the 'Range' key will be changed only if
                # limit is 0
                result["Range"] = []

    return result


@logger
def validate_required_group(command_data: dict) -> None:
    """
    Validates that if exactly one of each `required_group` have been given.
    Args:
        command_data (Dict): Command data.

    Returns:
        (None): Validates input.
    Raises:
        (DemistoException): If there exists a group in `required_group` whom arguments were given were not exactly one.
    """
    for group in command_data.get("required_groups", []):
        existing_args = [arg for arg in group if arg in inner_args_values or arg in args_values]
        if len(existing_args) != 1:
            raise DemistoException(f"Exactly one of the arguments {group} must be provided.")


@logger
def validate_depended_args(command_data: dict) -> None:
    """
    Validates that if one arg was given, and other arg is dependant on given arg, that it was given as well.
    Args:
        command_data (Dict): Command data.

    Returns:
        (None): Validates input.
    Raises:
        (DemistoException): If expected dependant arg is missing.
    """
    # Args that are required depending if other argument was given.
    for required_depended_arg, depended_on_arg in command_data.get("required_depended_args", {}).items():
        if depended_on_arg not in args_values and depended_on_arg not in inner_args_values:
            continue
        if required_depended_arg not in args_values and required_depended_arg not in inner_args_values:
            raise DemistoException(f"Argument {required_depended_arg} is required when argument {depended_on_arg} is given.")


@logger
def validate_at_most_one_group(command_data: dict) -> None:
    """
    Validates that for each group, at most one argument was given.
    Args:
        command_data (Dict): Command data.

    Returns:
        (None): Validates input.
    Raises:
        (DemistoException): If more than one arg in group was given.
    """
    #   At most one argument can be given
    for group in command_data.get("at_most_one_groups", []):
        existing_args = [arg for arg in group if arg in inner_args_values or arg in args_values]
        if len(existing_args) > 1:
            raise DemistoException(f"At most one of the following args can be given: {existing_args}")


@logger
def input_validation(command_name: str) -> None:
    """
    Takes the arguments received by the user and validates them.
    limit parameter - validates that it's a positive integer
    required groups - each command might have groups of parameters that only one argument from each group must be
                      provided. If there exists a group which none of the parameters in it were provided it's
                      considered an invalid input.
    A message will be printed explaining why the input is invalid.א
    Args:
        command_name: Name of the requested command
    Raises:
        DemistoException: Will be raised if input failed the validation
    """
    command_data = COMMANDS_ARGS_DATA[command_name]
    if limit := inner_args_values.get("limit"):
        try:
            if int(limit) < 1:
                raise ValueError
        except ValueError as exc:
            raise DemistoException("Limit parameter must be an integer bigger than 0") from exc

    validate_required_group(command_data)
    validate_depended_args(command_data)
    validate_at_most_one_group(command_data)


def generate_asset_tag_xml_request_body(args: dict[str, str], command_name: str):
    """generate asset tag xml request body according to passed command

    Args:
        args (Dict[str, str]): command arguments
        command_name (str): command name

    Returns:
        str: string representing xml
    """
    match command_name:
        case "qualys-asset-tag-list":
            ServiceRequest = ET.Element("ServiceRequest")
            if limit := args.get("limit"):
                preferences = ET.SubElement(ServiceRequest, "preferences")
                limit_results = ET.SubElement(preferences, "limitResults")
                limit_results.text = limit
            filters = ET.SubElement(ServiceRequest, "filters")
            criteria = ET.SubElement(filters, "Criteria")
            criteria.set("field", args.get("criteria", ""))
            criteria.set("operator", args.get("operator", ""))
            criteria.text = args.get("search_data", "")

        case "qualys-asset-tag-create" | "qualys-asset-tag-update":
            rule_text_arg = args.get("rule_text", "")
            rule_type_arg = args.get("rule_type", "")
            if rule_type_arg != "STATIC" and not rule_text_arg:
                raise DemistoException(
                    message="Rule Type argument is passed but Rule Text argument is missing."
                    + " Rule Text is optional only when Rule Type is 'STATIC'."
                )

            ServiceRequest = ET.Element("ServiceRequest")
            data = ET.SubElement(ServiceRequest, "data")
            tag = ET.SubElement(data, "Tag")
            name = ET.SubElement(tag, "name")
            name.text = args.get("name", "")
            rule_type = ET.SubElement(tag, "ruleType")
            rule_type.text = rule_type_arg
            if rule_text_arg:
                rule_text = ET.SubElement(tag, "ruleText")
                rule_text.text = rule_text_arg

            if criticality_score_arg := args.get("criticality_score"):
                criticality_score = ET.SubElement(tag, "criticalityScore")
                criticality_score.text = str(criticality_score_arg)

            if child_names := argToList(args.get("child_name")):
                children = ET.SubElement(tag, "children")
                action = ET.SubElement(children, "set")

                for child in child_names:
                    tag_simple = ET.SubElement(action, "TagSimple")
                    child_name_tag = ET.SubElement(tag_simple, "name")
                    child_name_tag.text = str(child)

            elif child_ids := argToList(args.get("child_to_remove")):
                children = ET.SubElement(tag, "children")
                action = ET.SubElement(children, "remove")
                for child in child_ids:
                    tag_simple = ET.SubElement(action, "TagSimple")
                    child_name_tag = ET.SubElement(tag_simple, "id")
                    child_name_tag.text = str(child)

    return ET.tostring(ServiceRequest)


def handle_asset_tag_request_parameters(args: dict[str, str], command_name: str) -> None:
    """Handle 'asset tag' command parameters related to the HTTP request.
    Add 'id' argument to URL suffix if required by the command.
    Generate a request body if required by the command.

    Args:
        args (Dict[str, str]): command arguments
        command_name (str): command name

    Returns:
        None: the function will make the necessary changes (if required by the command) and will return None.
    """
    # add 'id' argument to URL suffix if exists
    if id := args.get("id"):
        api_route = TAG_ASSET_COMMANDS_API_DATA[command_name].get("api_route")
        TAG_ASSET_COMMANDS_API_DATA[command_name]["api_route"] = urljoin(api_route, str(id))

    # generate request body if required by the command
    if TAG_ASSET_COMMANDS_API_DATA[command_name].get("request_body"):
        TAG_ASSET_COMMANDS_API_DATA[command_name]["request_body"] = generate_asset_tag_xml_request_body(args, command_name)


""" PARSERS """


@logger
def change_dict_keys(new_names_dict: dict[str, str], output_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Takes a dictionary and changes the names of the keys
    Args:
        new_names_dict: a dictionary with the old names as keys and their new names as their values
        output_dict: Dictionary with string keys
    Returns:
        Same dictionary but with keys with the new names or the same dictionary if the old keys don't exist
    Raises:
        TypeError: output_dict is not a dictionary
    """
    for key, new_name in new_names_dict.items():
        if key in output_dict:
            output_dict[new_name] = output_dict.pop(key)
    return output_dict


@logger
def change_list_dicts_names(command_parse_and_output_data: dict[str, Any], output: List[dict[str, Any]]) -> List[dict[str, Any]]:
    """
    Changing keys names of a list of dicts
    Args:
        command_parse_and_output_data (Dict): Data for parsing and creating output for a specific command
        output: list of dictionaries. all the dictionaries must have the same keys
    Returns:
        Same list but with dicts that have keys with the new names
    Raises:
        KeyError: can be raised by change_dict_keys
        TypeError: can be raised by change_dict_keys
    """
    new_names_dict = command_parse_and_output_data["new_names_dict"]

    for item in output:
        change_dict_keys(new_names_dict, item)
    return output


@logger
def parse_two_keys_dict(json_res: dict[str, Any]) -> dict[str, Any]:
    """
    Takes a dictionary in a specific format creates a new dictionary
    Args:
        json_res: Dictionary with two keys 'VALUE' and 'KEY'

    Returns: new dictionary with the 'KEY' value being the key and the value of the
             new key being the value of the key 'VALUE'
    Raises:
            KeyError: json_res doesn't have the expected keys
            TypeError: json_res is not a dictionary
    """
    res = {json_res["KEY"]: json_res["VALUE"]}
    return res


@logger
def parse_text_value_pairs_list(multiple_key_list: List[dict[str, Any]]) -> dict[str, Any]:
    """
    Creates a single dictionary from a list of dictionaries
    Args:
        multiple_key_list: List of dictionaries where each dictionary has the keys @value and #text
    Returns:
        A single dictionary where the keys are the '@value's and the values are the '#text's
    """
    parsed_dict = {}
    for obj in multiple_key_list:
        parsed_dict[obj["@value"]] = obj["#text"]
    return parsed_dict


def parse_raw_response(response: Union[bytes, requests.Response]) -> dict:
    """
    Parses raw response from Qualys.
    Tries to load as JSON. If fails to do so, tries to load as XML.
    If both fails, returns an empty dict.
    Args:
        response (Union[bytes, requests.Response]): Response from Qualys service.

    Returns:
        (Dict): Dict representing the data returned by Qualys service.
    """
    try:
        return json.loads(str(response))
    except Exception:
        try:
            return json.loads(xml2json(response))
        except Exception:
            return {}


@logger
def get_simple_response_from_raw(raw_response: Any) -> Union[Any, dict]:
    """
    Gets the simple response from a given JSON dict structure returned by Qualys service
    If object is not a dict, returns the response as is.
    Args:
        raw_response (Any): Raw response from Qualys service.

    Returns:
        (Union[Any, Dict]): Simple response path if object is a dict, else response as is.
    """
    simple_response = None
    if raw_response and isinstance(raw_response, dict):
        simple_response = raw_response.get("SIMPLE_RETURN", {}).get("RESPONSE", {})
    return simple_response


@logger
def format_and_validate_response(response: Union[bytes, requests.Response]) -> dict[str, Any]:
    """
    first tries to load the response as json if possible, if not will
    try to convert from xml to json, then it validates the response
    Args:
        response: Response received from Qualys API
    Returns:
        Dict: If response can be parsed and valid will return the parsed dictionary
        None: If response cant be parsed to json it will return None
    Raises:
        DemistoException: if the response has an error code
    """
    raw_response = parse_raw_response(response)
    simple_response = get_simple_response_from_raw(raw_response)
    if simple_response and simple_response.get("CODE"):
        raise DemistoException(f"\n{simple_response.get('TEXT')} \nCode: {simple_response.get('CODE')}")
    return raw_response


""" HANDLERS """


@logger
def handle_asset_tag_result(raw_response: requests.Response, command_name: str):
    """
    Handles asset tag commands. Parses, validates and finally returns the response parsed.
    Will raise an exception if needed.
    Args:
        raw_response (requests.Response): the raw result received from Qualys API command
        command_name (str): name of the command to handle
    Returns:
        CommandResults with data generated for the result given
    Raises:
        DemistoException: can be raised by parse_and_validate_response for bad input
    """

    formatted_response = format_and_validate_response(raw_response)

    if response_error_details := formatted_response.get("ServiceResponse", {}).get("responseErrorDetails"):
        raise DemistoException(response_error_details.get("errorMessage"))

    elif formatted_response.get("ServiceResponse", {}).get("count") == "0":
        return None

    elif path_list := COMMANDS_PARSE_AND_OUTPUT_DATA[command_name]["json_path"]:
        if len(path_list) == 0:
            return formatted_response
        response_requested_value = dict_safe_get(formatted_response, path_list)

        if not response_requested_value:
            raise ValueError
        return response_requested_value
    return None


@logger
def handle_general_result(raw_response: requests.Response, command_name: str) -> object:
    """
    Handles commands that don't return files, parses, validates and finally returns the response parsed .
    Args:
        raw_response (requests.Response): the raw result received from Qualys API command
        command_name (str): name of the command to handle
    Returns:
        CommandResults with data generated for the result given
    Raises:
        DemistoException: can be raised by parse_and_validate_response for bad input
    """
    path_list = COMMANDS_PARSE_AND_OUTPUT_DATA[command_name]["json_path"]
    formatted_response = format_and_validate_response(raw_response)

    if len(path_list) == 0:
        return formatted_response
    response_requested_value = dict_safe_get(formatted_response, path_list)

    if not response_requested_value:
        raise ValueError
    return response_requested_value


@logger
def handle_report_list_result(raw_response: requests.Response, command_name: str) -> object:
    """
    Handles report list command, parses, validates and finally returns the response parsed .
    Args:
        raw_response (requests.Response): the raw result received from Qualys API command
        command_name (str): name of the command to handle
    Returns:
        CommandResults with the report metadata
    Raises:
        DemistoException: can be raised if there is no report for given id
    """
    response_requested_value = handle_general_result(raw_response, command_name)

    if is_empty_result(response_requested_value) and (report_id := demisto.args().get("id")):
        raise DemistoException(f"No report exist for the id {report_id}")

    return response_requested_value


@logger
def handle_fetch_result(raw_response: Union[bytes, requests.Response], command_name: str) -> dict:
    """
    Handles fetch file commands
    Args:
        raw_response (requests.Response): response received from qualys
        command_name (str): name of the command to handle
    Returns:
        A Demisto war room entry
    """
    command_parse_and_output_data = COMMANDS_PARSE_AND_OUTPUT_DATA[command_name]

    format_and_validate_response(raw_response)
    file_id = args_values[command_parse_and_output_data["file_id"]]
    file_format = inner_args_values["file_format"]
    file_name = f"{command_parse_and_output_data['file_prefix']}_{file_id}.{file_format}"

    file_type = entryTypes["entryInfoFile"]
    entry = fileResult(file_name, raw_response, file_type)

    return entry


""" OUTPUT BUILDERS """


@logger
def build_one_value_parsed_output(**kwargs) -> tuple[dict[str, Any], str]:
    """
    creates a dictionary with a single key for command_results outputs field
    and a markdown table with a single value
    Args:
        **kwargs:
                command_parse_and_output_data (Dict): Data for parsing and creating output for a specific command
                handled_result (Dict): response received from Qualys API
    Returns:
        Tuple containing a dictionary with a single key and a markdown table string
    Raises:
        KeyError: will be raised by parse_two_keys_dict if response has unexpected keys
        TypeError: will be raised by  parse_two_keys_dict response is not a dictionary
    """
    command_parse_and_output_data = kwargs["command_parse_and_output_data"]
    collection_name = command_parse_and_output_data.get("collection_name")
    response = kwargs["handled_result"]
    output = parse_two_keys_dict(generate_list_dicts(response[collection_name]))
    output["DATETIME"] = response.get("DATETIME")
    output["TEXT"] = response.get("TEXT")
    readable_output = tableToMarkdown(name=command_parse_and_output_data["table_name"], t=output)
    return output, readable_output


@logger
def build_single_text_output(**kwargs) -> tuple[dict[str, Any], str]:
    """
    creates output with the dictionary returned from the request and the text attached to it
    Args:
        **kwargs:
                handled_result (Dict): response received from Qualys API
    Returns:
            Tuple containing a dictionary and the text returned in the response
    """
    output = kwargs["handled_result"]
    readable_output = output["TEXT"]
    return output, readable_output


@logger
def build_unparsed_output(**kwargs) -> tuple[dict[str, Any], str]:
    """
    creates output with the dictionary returned from the request and a markdown table generated
    from the unparsed response received
    Args:
        **kwargs:
                handled_result (Dict): response received from Qualys API
                command_parse_and_output_data (Dict): Data for parsing and creating output for a specific command
    Returns:
            Tuple containing a dictionary and a markdown table generated from the response
    """
    command_parse_and_output_data = kwargs["command_parse_and_output_data"]
    unparsed_output = kwargs["handled_result"]
    original_amount = None
    limit_msg = ""

    if "limit" in inner_args_values and isinstance(unparsed_output, list):
        original_amount = len(unparsed_output)
        unparsed_output = limit_result(unparsed_output, inner_args_values["limit"])
    if original_amount and original_amount > int(inner_args_values["limit"]):
        limit_msg = f"Currently displaying {inner_args_values['limit']} out of {original_amount} results."
    readable_output = tableToMarkdown(name=f"{command_parse_and_output_data['table_name']}\n{limit_msg}", t=unparsed_output)

    return unparsed_output, readable_output


@logger
def build_ip_list_output(**kwargs) -> tuple[dict[str, List[str]], str]:
    """
    creates output with a new dictionary parsed from the original response and two markdown tables, generated
    for commands which output is a dictionary containing two lists, one of single IPs and the other of ranges of ips.
    Args:
        **kwargs:
                handled_result (Dict): response received from Qualys API
                command_parse_and_output_data (Dict): Data for parsing and creating output for a specific command
    Returns:
            Tuple containing a dictionary created and a markdown table generated from the response
    Raises:
            KeyError: can be raised by either change_dict_keys or create_ip_list_dicts
            TypeError: can be raised by either change_dict_keys or create_ip_list_dicts
    """
    command_parse_and_output_data = kwargs["command_parse_and_output_data"]
    handled_result = kwargs["handled_result"]
    readable_output = ""
    original_amount = None
    limit_msg = ""

    if "STATUS" in handled_result:
        readable_output += f'### Current Status: {handled_result["STATUS"]}\n'

    if command_parse_and_output_data["collection_name"] in handled_result:
        asset_collection = handled_result[command_parse_and_output_data["collection_name"]]
        handled_result = change_dict_keys(command_parse_and_output_data["new_names_dict"], asset_collection)

        if "limit" in inner_args_values and inner_args_values["limit"]:
            original_amount = calculate_ip_original_amount(handled_result)
            handled_result = limit_ip_results(handled_result, int(inner_args_values["limit"]))

        if original_amount and original_amount > int(inner_args_values["limit"]):
            limit_msg = f"Currently displaying {inner_args_values['limit']} out of {original_amount} results."

        ip_and_range_list = create_single_host_list(handled_result)
        dicts_of_ranges_and_ips = build_ip_and_range_dicts(ip_and_range_list)
        readable_output = f"{limit_msg}\n"
        readable_output += create_ip_list_markdown_table(dicts_of_ranges_and_ips)

    return handled_result, readable_output


@logger
def build_multiple_values_parsed_output(**kwargs) -> tuple[List[Any], str]:
    """
    When the response from Qualys has a list of dictionaries this function will get this list and
    will generate a markdown table from it
    Args:
        **kwargs:
                handled_result (Dict): response received from Qualys API
                command_parse_and_output_data (Dict): Data for parsing and creating output for a specific command
    Returns:
            Tuple containing a List of dictionaries parsed from the original response and a markdown table
            generated from the parsed response
    """
    command_parse_and_output_data = kwargs["command_parse_and_output_data"]
    handled_result = kwargs["handled_result"]
    if collection_name := command_parse_and_output_data.get("collection_name"):
        asset_collection = handled_result[collection_name]
    else:
        asset_collection = handled_result
    original_amount = None
    limit_msg = ""
    parsed_output = generate_list_dicts(asset_collection)

    if "limit" in inner_args_values and inner_args_values["limit"] and isinstance(parsed_output, list):
        original_amount = len(parsed_output)
        parsed_output = limit_result(parsed_output, inner_args_values["limit"])

    if original_amount and original_amount > int(inner_args_values["limit"]):
        limit_msg = f"Currently displaying {inner_args_values['limit']} out of {original_amount} results."
    headers = command_parse_and_output_data.get("table_headers") if command_parse_and_output_data.get("table_headers") else None
    readable_output = tableToMarkdown(
        name=f"{command_parse_and_output_data['table_name']}\n{limit_msg}", t=parsed_output, headers=headers
    )
    return parsed_output, readable_output


@logger
def build_host_list_detection_outputs(**kwargs) -> tuple[List[Any], str]:
    """
    Builds the outputs and readable output for host list detection.
    Args:
        kwargs: Output builder args.

    Returns:
        (Tuple[List[Any], str]): Outputs and readable outputs.
    """
    command_parse_and_output_data = kwargs["command_parse_and_output_data"]
    handled_result = kwargs["handled_result"]
    if collection_name := command_parse_and_output_data.get("collection_name"):
        asset_collection = handled_result[collection_name]
    else:
        asset_collection = handled_result
    original_amount = None
    limit_msg = ""
    parsed_output = generate_list_dicts(asset_collection)
    parsed_output = parsed_output if isinstance(parsed_output, List) else [parsed_output]
    if "limit" in inner_args_values and inner_args_values["limit"] and isinstance(parsed_output, list):
        original_amount = len(parsed_output)
        parsed_output = limit_result(parsed_output, inner_args_values["limit"])

    if original_amount and original_amount > int(inner_args_values["limit"]):
        limit_msg = f"Currently displaying {inner_args_values['limit']} out of {original_amount} results."
    readable = ""
    for output in parsed_output:
        headers = ["ID", "IP", "DNS_DATA"]
        ip = output.get("IP")
        readable_output = {
            "ID": output.get("ID"),
            "IP": ip,
            "DNS_DATA": {k: v for k, v in output.get("DNS_DATA", {}).items() if v is not None},
        }
        if detections := output.get("DETECTION_LIST", {}).get("DETECTION", []):
            detections = detections if isinstance(detections, List) else [detections]
            for detection in detections:
                qid = "QID: " + detection.get("QID")
                headers.append(qid)
                readable_output[qid] = detection.get("RESULTS")
        readable += tableToMarkdown(f"Host Detection List - {ip}\n{limit_msg}", readable_output, removeNull=True, headers=headers)
    return parsed_output, readable


@logger
def build_changed_names_output(**kwargs) -> tuple[List[Any], str]:
    """
    Takes the output and changes the output fields names as described in the command data
    Args:
        **kwargs:
                handled_result (Dict): response received from Qualys API
                command_parse_and_output_data (Dict): Data for parsing and creating output for a specific command
    Returns:
            Tuple containing a dictionary and a markdown table generated from the response
    """
    command_parse_and_output_data = kwargs["command_parse_and_output_data"]
    output = kwargs["handled_result"]

    output = change_list_dicts_names(command_parse_and_output_data, output)
    readable_output = tableToMarkdown(name=command_parse_and_output_data["table_name"], t=output)

    return output, readable_output


@logger
def build_multiple_text_options_output(**kwargs) -> tuple[None, str]:
    """
    When there's no need to build output from the response but output text is based on command's action requested
    this function will take the text based on the action and will return it
    Args:
        **kwargs:
                command_parse_and_output_data (Dict): Data for parsing and creating output for a specific command
    Returns:
            Tuple containing None and text based on the action requested
    """
    command_parse_and_output_data = kwargs["command_parse_and_output_data"]
    action = args_values["action"]

    readable_output = command_parse_and_output_data["output_texts"][action]

    return None, readable_output


@logger
def build_text_value_pairs_parsed_output(**kwargs) -> tuple[dict[str, Any], str]:
    """
    A command might have multiple key value pairs. The data is returned as a list of dictionaries, each dictionary has
    a key named '@value' which holds the name of the field, and a key named '#text' which holds the
    value of the same field.
    Args:
        **kwargs:
                handled_result (Dict): response received from Qualys API
                command_parse_and_output_data (Dict): Data for parsing and creating output for a specific command
    Returns:
        Tuple containing a dictionary created from those key-value pairs and a markdown table as a string
    """
    command_parse_and_output_data = kwargs["command_parse_and_output_data"]
    output = kwargs["handled_result"]

    parsed_output = parse_text_value_pairs_list(output)
    readable_output = tableToMarkdown(name=command_parse_and_output_data["table_name"], t=parsed_output)

    return parsed_output, readable_output


@logger
def build_ip_list_from_single_value(**kwargs) -> tuple[dict[str, Any], str]:
    """
    Given a command response that has a value which contains a list of ips in the following format:
    '1.1.1.1','1.1.1.2'
    this function will add each ip separately to the dictionary of results
    Args:
        **kwargs:
                handled_result (Dict): response received from Qualys API
    Returns:
        Tuple containing a dictionary created from those key-value pairs and a markdown table as a string
    """
    unparsed_output = kwargs["handled_result"]
    readable_output = f"### {unparsed_output['KEY']}\n"
    if unparsed_output["VALUE"]:
        list_of_hosts = unparsed_output["VALUE"].split(",")
        dicts_of_ranges_and_ips = build_ip_and_range_dicts(list_of_hosts)
        readable_output += create_ip_list_markdown_table(dicts_of_ranges_and_ips)
    else:
        readable_output = "No IPs were found"

    return unparsed_output, readable_output


@logger
def build_tag_asset_output(**kwargs) -> tuple[List[Any], str]:
    command_parse_and_output_data = kwargs["command_parse_and_output_data"]
    handled_result = kwargs["handled_result"]

    if human_readable_massage := command_parse_and_output_data.get("human_readable_massage"):
        readable_output = human_readable_massage
        return handled_result, readable_output

    if type(handled_result) is dict and (children_list := handled_result.get("children", {}).get("list", {}).get("TagSimple")):
        handled_result["childTags"] = children_list
        handled_result.pop("children")

    readable_output = tableToMarkdown(
        name=command_parse_and_output_data.get("table_name"),
        t=handled_result,
        headers=command_parse_and_output_data.get("table_headers"),
        is_auto_json_transform=True,
        removeNull=True,
        headerTransform=pascalToSpace,
    )
    return handled_result, readable_output


def get_partial_response(response: str, start: str, end: str):
    """Cut response string from start to end tokens."""
    if start not in response or end not in response:
        return None
    start_index = response.index(start) + len(start)
    end_index = response.index(end)
    result = response[start_index:end_index].strip()
    if result.startswith(WARNING):
        result = result.replace(WARNING, "").strip()
    return result


def csv2json(csv_data: str):
    """Converts data from csv to json
    Args:
        csv_data: data in csv format
    Returns:
        the same data in json formal
    """
    reader = csv.DictReader(io.StringIO(csv_data))
    json_data = list(reader)
    return json_data


def get_next_page_from_url(url, field):
    """
    Get the next page field from url.
    """
    match = re.search(rf"{field}=(\d+)", url)
    res = match.group(1) if match else None
    return res


def get_next_page_activity_logs(footer):
    """
    Extracts the next token from activity logs response.
    """
    if isinstance(footer, list):
        footer = footer[0]
    next_url = footer.get("URL", "")
    max_id = get_next_page_from_url(next_url, "id_max")
    return max_id


def handle_host_list_detection_result(raw_response: requests.Response) -> tuple[list, Optional[str]]:
    """
    Handles Host list detection response - parses xml to json and gets the list
    Args:
        raw_response (requests.Response): the raw result received from Qualys API command
    Returns:
        List with data generated for the result given
    """
    demisto.debug("Going to parse raw_response into the hosts list")
    formatted_response = parse_raw_response(raw_response)
    simple_response = get_simple_response_from_raw(formatted_response)
    if simple_response and simple_response.get("CODE"):
        raise DemistoException(f"\n{simple_response.get('TEXT')} \nCode: {simple_response.get('CODE')}")

    response_requested_value = dict_safe_get(
        formatted_response, ["HOST_LIST_VM_DETECTION_OUTPUT", "RESPONSE", "HOST_LIST", "HOST"]
    )
    response_next_url = dict_safe_get(
        formatted_response, ["HOST_LIST_VM_DETECTION_OUTPUT", "RESPONSE", "WARNING", "URL"], default_return_value=""
    )
    if isinstance(response_requested_value, dict):
        response_requested_value = [response_requested_value]

    demisto.debug(f"Extracted a list of {len(response_requested_value)} hosts, and next url - {response_next_url}")

    return response_requested_value, str(response_next_url)


def handle_vulnerabilities_result(raw_response: requests.Response) -> list:
    """
    Handles vulnerabilities response - parses xml to json and gets the list
    Args:
        raw_response (requests.Response): the raw result received from Qualys API command
    Returns:
        List with data generated for the result given
    """
    formatted_response = parse_raw_response(raw_response)

    vulnerabilities = dict_safe_get(formatted_response, ["KNOWLEDGE_BASE_VULN_LIST_OUTPUT", "RESPONSE", "VULN_LIST", "VULN"])
    if isinstance(vulnerabilities, dict):
        vulnerabilities = [vulnerabilities]

    return vulnerabilities


def remove_last_events(events, time_to_remove, time_field):
    """Removes events with certain time.
    Args:
        events: list of events to remove the time from
        time_to_remove: remove events with this time
        time_field: the field name where the time is
    """
    new_events = []
    for event in events:
        if event.get(time_field) == time_to_remove:
            demisto.debug(f"Removed activity log event with time: {time_to_remove}, log: {event}")
        else:
            new_events.append(event)
    return new_events


def add_fields_to_events(events, time_field_path, event_type_field):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
        time_field_path: the list of fields to get _time from
        event_type_field: type field in order to distinguish between the API's
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            event["_time"] = dict_safe_get(event, time_field_path)
            event["event_type"] = event_type_field


def truncate_asset_size(asset):
    if results := asset.get("DETECTION", {}).get("RESULTS"):
        results_size = get_size_of_object(results)
        if results_size > ASSET_SIZE_LIMIT:
            host_id = asset.get("ID") or "NO_ID"
            detection_id = asset.get("DETECTION", {}).get("UNIQUE_VULN_ID", "No detection")
            detection_str = f" detection ID: {detection_id}" if detection_id else ""
            results_characters_lim = 10000

            asset["DETECTION"]["RESULTS"] = results[:results_characters_lim]
            asset["isTruncated"] = True
            demisto.debug(f"Truncated Asset ID: {host_id}{detection_str} to {results_characters_lim}")
            demisto.debug(json.dumps(asset))

        # For extra debugging in case other/additional keys has oversize data
        for key, val in asset.items():
            if (val_size := get_size_of_object(val)) > ASSET_SIZE_LIMIT:  # 1 MB
                demisto.debug(f'Data under key "{key}" has size of {val_size}:\n' f"{str(val)[:10000]}...")


def get_detections_from_hosts(hosts):
    """
    Parses detections from hosts.
    Each host contains list of detections:
    {'ID':1,
    'IP': '1.1.1.1',
    'LAST_VM_SCANNED_DATE': '01-01-2020',
    'DETECTION_LIST': {'DETECTION': [first_detection_data, second_detection, ...]}
    'additional_fields': ...
    }

    The function parses the data in the following way:
    {''ID':1,
    'IP': '1.1.1.1',
    'LAST_VM_SCANNED_DATE': '01-01-2020',
    'DETECTION': first_detection_data
    'additional_fields': ...
    },
    {'ID':1,
    'IP': '1.1.1.1',
    'LAST_VM_SCANNED_DATE': '01-01-2020',
    'DETECTION': second_detection_data
    'additional_fields': ...
    }
    ....

    :param hosts: list of hosts that contains detections.
    :return: parsed events.
    """
    demisto.debug(f"Received {len(hosts)} hosts for extraction")
    fetched_assets = []
    for host in hosts:
        if check_fetch_assets_duration_time_exceeded(EXECUTION_START_TIME):  # Check that execution time is not too long
            return [], True
        detections_list = host.get("DETECTION_LIST", {}).get("DETECTION") or [{}]

        if not isinstance(detections_list, list):  # In case detections_list = {}
            detections_list = [detections_list]

        for detection in detections_list:
            new_detection = copy.deepcopy(host)
            del new_detection["DETECTION_LIST"]
            new_detection["DETECTION"] = detection
            fetched_assets.append(new_detection)
            truncate_asset_size(new_detection)

    demisto.debug(f"Extracted {len(fetched_assets)} assets from hosts")
    return fetched_assets, False


def send_assets_and_vulnerabilities_to_xsiam(
    assets: list,
    vulnerabilities: list,
    cumulative_assets_count: int,
    cumulative_vulns_count: int,
    has_next_page: bool,
    snapshot_id: str,
) -> None:
    """Sends assets and vulnerabilities to their respective snapshot datasets without updating module health.
    `demisto.updateModuleHealth()` should be called seperately afterwards uisng the cumulative counts.

    Args:
        assets (list): List of host detections (assets) dictionaries.
        vulnerabilities (list): List of vulnerabilities dictionaries.
        cumulative_assets_count (int): Total count of assets collected since resetting last run object.
        cumulative_vulns_count (int): Total count of vulnerabilities collected since resetting last run object.
        has_next_page (bool): Whether there is a next assets page url (indicates not done pulling all results).
        snapshot_id (str): Snapshot ID of the dataset (use the same snapshot ID to add more data to the same dataset snapshot).
    """
    # Set to 1 if not done pulling to signal to the server that the dataset snapshot is not yet complete
    total_assets_to_report = 1 if has_next_page else cumulative_assets_count
    total_vulns_to_report = 1 if has_next_page else cumulative_vulns_count

    demisto.debug(f"Sending {len(assets)} assets to XSIAM. " f"Total assets collected so far: {cumulative_assets_count}")

    send_data_to_xsiam(
        data=assets,
        vendor=VENDOR,
        product="assets",
        data_type="assets",
        snapshot_id=snapshot_id,
        items_count=str(total_assets_to_report),
        should_update_health_module=False,
    )

    demisto.debug(
        f"Sending {len(vulnerabilities)} vulnerabilities to XSIAM. "
        f"Total vulnerabilities collected so far: {cumulative_vulns_count}"
    )

    send_data_to_xsiam(
        data=vulnerabilities,
        vendor=VENDOR,
        product="vulnerabilities",
        data_type="assets",
        snapshot_id=snapshot_id,
        items_count=str(total_vulns_to_report),
        should_update_health_module=False,
    )


def get_activity_logs_events(client, since_datetime, max_fetch, next_page=None) -> tuple[Optional[list], dict]:
    """Get logs activity from qualys
    API response returns events sorted in descending order. We are saving the next_page param and
    sending next request with next_page arg if needed. Saving the newest event fetched.
    We are deleting the newest event each time to avoid duplication.
    Args:
        client: Qualys client
        since_datetime: datetime to get events from
        max_fetch: max number of events to return
        next_page: pagination marking
    Returns:
        Logs activity events, Next run datetime
    """
    demisto.debug(f"Starting to fetch activity logs events: since_datetime={since_datetime}, next_page={next_page}")
    activity_logs = client.get_user_activity_logs(since_datetime=since_datetime, max_fetch=max_fetch, next_page=next_page)
    activity_logs_events = (
        csv2json(get_partial_response(activity_logs, BEGIN_RESPONSE_LOGS_CSV, END_RESPONSE_LOGS_CSV) or activity_logs) or []
    )
    footer_json = csv2json(get_partial_response(activity_logs, BEGIN_RESPONSE_FOOTER_CSV, END_RESPONSE_FOOTER_CSV)) or {}
    new_next_page = get_next_page_activity_logs(footer_json)
    demisto.debug(f"Got activity logs events from server: {len(activity_logs_events)=}.")

    newest_event_time = activity_logs_events[0].get("Date") if activity_logs_events else since_datetime

    if not next_page:
        activity_logs_events = remove_last_events(activity_logs_events, newest_event_time, "Date")
    add_fields_to_events(activity_logs_events, ["Date"], "activity_log")

    next_run_dict = {
        ACTIVITY_LOGS_NEWEST_EVENT_DATETIME: newest_event_time,
        ACTIVITY_LOGS_NEXT_PAGE: new_next_page,
        ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN: since_datetime,
    }
    demisto.debug(f"Done to fetch activity logs events: {next_run_dict=}, sending {len(activity_logs_events)} events.")
    return activity_logs_events, next_run_dict


def get_host_list_detections_events(client, since_datetime, next_page="", limit=HOST_LIMIT, is_test=False) -> tuple:
    """Get host list detections from qualys
    Args:
        client: Qualys client
        next_page: pagination marking
        since_datetime: The start fetch date.
        limit: The limit of the host list detections
        is_test: Indicates whether it's test-module run or regular run.
    Returns:
        Host list detections assets
    """
    demisto.debug("Pulling host list detections")
    assets: list = []
    host_list_detections, set_new_limit = client.get_host_list_detection(
        since_datetime=since_datetime, next_page=next_page, limit=limit
    )
    if not set_new_limit:
        host_list_assets, next_url = handle_host_list_detection_result(host_list_detections)

        assets, set_new_limit = get_detections_from_hosts(host_list_assets) if (host_list_assets and not is_test) else ([], False)
        demisto.debug(f"Parsed detections from hosts, created {len(assets)=} assets.")

        if not set_new_limit:
            add_fields_to_events(assets, ["DETECTION", "FIRST_FOUND_DATETIME"], "host_list_detection")
            next_page = get_next_page_from_url(next_url, "id_min")

    return assets, next_page, set_new_limit


def get_vulnerabilities(client: Client, since_datetime: str | None = None, detection_qids: list | None = None) -> list:
    """Get vulnerabilities list from qualys
    Args:
        client (Client): Qualys client
        since_datetime (str | None): Optional start fetch date.
        detection_qids (list | None): Optional list of Qualys host detection IDs.
    Returns:
        list vulnerabilities
    """
    demisto.debug("Starting to fetch vulnerabilities")

    if since_datetime:
        host_list_detections = client.get_vulnerabilities(since_datetime=since_datetime)
        vulnerabilities = handle_vulnerabilities_result(host_list_detections) or []

    elif detection_qids:
        vulnerabilities = []
        for qids_batch in batch(detection_qids, QIDS_BATCH_SIZE):
            host_list_detections = client.get_vulnerabilities(detection_qids=",".join(qids_batch))
            vulnerabilities_batch = handle_vulnerabilities_result(host_list_detections) or []
            vulnerabilities.extend(vulnerabilities_batch)

    else:
        raise ValueError("Either 'since_datetime' or 'detection_qids' need to be specified")

    demisto.debug(f"Parsed detections from hosts, got {len(vulnerabilities)=} vulnerabilities.")
    return vulnerabilities


def fetch_assets(client: Client, assets_last_run):
    """Fetches host list detections
    Args:
        client: Qualys client
        assets_last_run: The last run.
    Return:
        assets: assets to push to xsiam
        vulnerabilities: vulnerabilities to push to xsiam
    """
    since_datetime = assets_last_run.get("since_datetime", "")
    next_page = assets_last_run.get("next_page", "")
    total_assets = assets_last_run.get("total_assets", 0)
    snapshot_id = str(assets_last_run.get("snapshot_id", str(round(time.time() * 1000))))
    limit = assets_last_run.get("limit", HOST_LIMIT)

    demisto.debug(f"Starting fetch process for assets {snapshot_id=}")

    if not since_datetime:
        since_datetime = arg_to_datetime(ASSETS_FETCH_FROM).strftime(ASSETS_DATE_FORMAT)  # type: ignore[union-attr]

    assets, next_run_page, set_new_limit = get_host_list_detections_events(client, since_datetime, next_page, limit)

    total_assets += len(assets)
    stage = "assets" if next_run_page else "vulnerabilities"
    amount_to_report = 1 if next_run_page else total_assets  # We report 1 as long as we have not finished pulling

    new_last_run = {
        "stage": stage,
        "next_page": next_run_page,
        "total_assets": total_assets,
        "since_datetime": since_datetime,
        "snapshot_id": snapshot_id,
        "nextTrigger": "0",
        "type": FETCH_COMMAND.get("assets"),
    }

    return assets, new_last_run, amount_to_report, snapshot_id, set_new_limit


def check_fetch_assets_duration_time_exceeded(start_time: float) -> bool:
    """Checks if the 'fetch-assets' command execution time exceeded the defined value.

    Args:
        start_time (float): The time in seconds since the Epoch (Unix time).

    Returns:
        bool: True if execution time has been exceeded, False otherwise.
    """
    elapsed_time = time.time() - start_time
    if elapsed_time > FETCH_ASSETS_COMMAND_TIME_OUT:
        demisto.debug(
            f"Exceeded the defined exceution timeout: {FETCH_ASSETS_COMMAND_TIME_OUT}. Elapsed time: {elapsed_time}. "
            "Data will not be sent to XSIAM due to insufficient remaining time. The limit will be reduced for future runs."
        )
        return True
    return False


def set_assets_last_run_with_new_limit(last_run: dict, limit: int) -> dict:
    """Updates last assets run by setting `limit` to half, `nextTrigger` to 0, and `type` to 1 (assets).
    This instructs the server to immediately trigger the next assets fetch iteration.

    Args:
        last_run (dict): Last assets run dictionary.
        limit (int): Host detections limit.

    Returns:
        dict: Updated next assets run.
    """
    new_limit = int(limit / 2) if limit > 1 else 1
    demisto.debug(f"Setting host limit to: {new_limit}")
    last_run["limit"] = new_limit
    last_run["nextTrigger"] = "0"  # Trigger next fetch iteration immediately
    last_run["type"] = FETCH_COMMAND["assets"]  # Set next fetch iteration to type 'assets'
    return last_run


def fetch_vulnerabilities(client: Client, last_run: dict[str, Any], detection_qids: list | None = None):
    """Fetches vulnerabilities
    Args:
        client (Client): Qualys client
        last_run (dict): The last run.
        detection_qids (list | None): List of Qualys host detection IDs.
    Return:
        vulnerabilities: vulnerabilities to push to xsiam
        last_run: The  new last run to save.
    """
    demisto.debug("Starting fetch for vulnerabilities")

    if detection_qids:
        demisto.debug(f"Getting vulnerabilities for {len(detection_qids)} QIDs")
        vulnerabilities = get_vulnerabilities(client, detection_qids=detection_qids)
    else:
        since_datetime = (
            last_run.get("since_datetime") or arg_to_datetime(ASSETS_FETCH_FROM, required=True).strftime(ASSETS_DATE_FORMAT)  # type: ignore[union-attr]
        )
        demisto.debug(f"Getting vulnerabilities modified after {since_datetime}")
        vulnerabilities = get_vulnerabilities(client, since_datetime=since_datetime)

    new_last_run = DEFAULT_LAST_ASSETS_RUN

    return vulnerabilities, new_last_run


def fetch_events(
    client: Client,
    last_run,
    first_fetch_time,
    fetch_function,
    newest_event_field,
    next_page_field,
    previous_run_time_field,
    max_fetch: Optional[int] = 0,
):
    """Fetches activity logs and host list detections
    Args:
        client: Qualys client
        last_run: last fetch time
        first_fetch_time: when start to fetch from
        fetch_function: function that gets the events
        max_fetch: max number of items to return (0 to return all)
        newest_event_field
        next_page_field
        previous_run_time_field
    Return:
        next_last_run: where to fetch from next time
        event: events to push to xsiam
    """
    demisto.debug(f"Starting fetch for {fetch_function.__name__}, last run: {last_run}")
    newest_event_time = last_run.get(newest_event_field) if last_run else None
    next_page = last_run.get(next_page_field)
    previous_time_field = last_run.get(previous_run_time_field)

    if not newest_event_time:
        newest_event_time = first_fetch_time

    time_to_fetch = newest_event_time if not next_page else previous_time_field

    events, new_next_run = fetch_function(client, time_to_fetch, max_fetch, next_page)

    updated_next_run = {previous_run_time_field: time_to_fetch}
    new_next_page = new_next_run.get(next_page_field)

    # if the fetch is not during the pagination (fetched without next_page)
    if not next_page:
        # update the newest event
        updated_next_run[newest_event_field] = new_next_run.get(newest_event_field)

    # update if there is next page and this fetch is not over
    updated_next_run[next_page_field] = new_next_page

    if last_fetch_time := new_next_run.get(HOST_LAST_FETCH):
        updated_next_run[HOST_LAST_FETCH] = last_fetch_time

    demisto.info(f"Sending {len(events)} to XSIAM. updated_next_run={updated_next_run}.")
    return updated_next_run, events


def get_activity_logs_events_command(client: Client, args, first_fetch_time):
    """
    Args:
        client: Qualys client
        args: Demisto args for this command: limit and since_datetime
        first_fetch_time: first fetch time
    Retuns:
        Command results with activity logs

    """
    limit = arg_to_number(args.get("limit", 50))
    offset = arg_to_number(args.get("offset", 0))
    since_datetime = arg_to_datetime(args.get("since_datetime"))
    since_datetime = since_datetime.strftime(DATE_FORMAT) if since_datetime else first_fetch_time
    activity_logs_events, _ = get_activity_logs_events(
        client=client,
        since_datetime=since_datetime,
        max_fetch=0,
    )
    limited_activity_logs_events = activity_logs_events[offset : limit + offset]  # type: ignore[index,operator]
    activity_logs_hr = tableToMarkdown(name="Activity Logs", t=limited_activity_logs_events)
    results = CommandResults(
        readable_output=activity_logs_hr,
        raw_response=limited_activity_logs_events,
    )

    return limited_activity_logs_events, results


def test_module(client: Client, params: dict[str, Any], first_fetch_time: str) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    is_fetch_events = params.get("isFetchEvents") or False
    is_fetch_assets = params.get("isFetchAssets") or False

    if is_fetch_assets or is_fetch_events:
        if is_fetch_events:
            fetch_events(
                client=client,
                last_run={},
                first_fetch_time=first_fetch_time,
                max_fetch=1,
                fetch_function=get_activity_logs_events,
                newest_event_field=ACTIVITY_LOGS_NEWEST_EVENT_DATETIME,
                next_page_field=ACTIVITY_LOGS_NEXT_PAGE,
                previous_run_time_field=ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN,
            )
        if is_fetch_assets:
            since_datetime = arg_to_datetime("1 hour").strftime(ASSETS_DATE_FORMAT)  # type: ignore[union-attr]
            get_host_list_detections_events(client=client, since_datetime=since_datetime, limit=1, is_test=True)
    else:
        build_args_dict({"launched_after_datetime": TEST_FROM_DATE}, COMMANDS_ARGS_DATA["test-module"], False)
        client.command_http_request(COMMANDS_API_DATA["test-module"])

    return "ok"


@logger
def qualys_command_flow_manager(
    client: Client, args: dict[str, str], command_name: str, command_methods: dict[str, Callable]
) -> Optional[CommandResults]:
    """
    Args:
        client: Client object for making a http request
        args: Dictionary of the arguments entered by the user for the command
        command_name: string of the command name
        command_methods: Dictionary of handler and output builder of the specific command
    Returns:
        Results received by the command or None if it's a file download
    Raises:
        DemistoException: will be raised when request to Qualys API failed
    """

    # handle asset tag command parameters for HTTP request
    if command_name in TAG_ASSET_COMMANDS_API_DATA:
        handle_asset_tag_request_parameters(args, command_name)

        # args_values is passed in this code as 'params' in _http_request function (generated in build_args_dict function).
        # because asset tag requests pass their arguments through request body rather than parameters in the URL suffix,
        # args_values is Nulled in this case.
        result = client.command_http_request(TAG_ASSET_COMMANDS_API_DATA[command_name])
    else:
        # Build the API and internal arguments of the command
        build_args_dict(args, COMMANDS_ARGS_DATA[command_name], False)
        build_args_dict(args, COMMANDS_ARGS_DATA[command_name], True)

        # Validate input provided by the user
        input_validation(command_name)

        # Make an API request
        result = client.command_http_request(COMMANDS_API_DATA[command_name])

    # Call the command's handler
    handled_result = command_methods["result_handler"](result, command_name)

    if command_methods.get("output_builder"):
        if is_empty_result(handled_result):
            return CommandResults(raw_response=result, readable_output="No items found")

        # Call the command's output builder
        outputs, readable_output = command_methods["output_builder"](
            handled_result=handled_result, command_parse_and_output_data=COMMANDS_PARSE_AND_OUTPUT_DATA[command_name]
        )
        if not COMMANDS_CONTEXT_DATA[command_name]["context_prefix"]:
            outputs, result = None, None
        return CommandResults(
            outputs_prefix=COMMANDS_CONTEXT_DATA[command_name]["context_prefix"],
            outputs_key_field=COMMANDS_CONTEXT_DATA[command_name]["context_key"],
            outputs=outputs,
            raw_response=result,
            readable_output=readable_output,
        )
    else:
        # No need to build output
        return handled_result


def fetch_assets_and_vulnerabilities_by_date(client: Client, last_run: dict[str, Any]) -> None:
    """
    Fetches host dectections (assets) by VM scan date and vulnerabilities by last modified date in two seperate fetch stages.

    Args:
        client (Client): Qualys client.
        last_run (dict): Last assets run dictionary.
    """
    fetch_stage = last_run.get("stage", "assets")

    if fetch_stage == "assets":
        demisto.debug(f"Starting fetch for assets, {EXECUTION_START_TIME=}")
        assets, new_last_run, total_assets_to_report, snapshot_id, set_new_limit = fetch_assets(client, last_run)

        # If assets request read timeout (set_new_limit flag is True) or exceeded max exceution time, make next API call smaller
        if set_new_limit or check_fetch_assets_duration_time_exceeded(EXECUTION_START_TIME):
            demisto.debug(
                f"Reducing limit for assets next run due to timeout. Set new limit: {set_new_limit}. "
                f"Elapsed time: {time.time() - EXECUTION_START_TIME}."
            )
            new_last_run = set_assets_last_run_with_new_limit(last_run, last_run.get("limit", HOST_LIMIT))
        else:
            cumulative_assets_count: int = new_last_run["total_assets"]
            demisto.debug(f"Sending {len(assets)} assets to XSIAM. " f"Total assets collected so far: {cumulative_assets_count}")

            send_data_to_xsiam(
                data=assets,
                vendor=VENDOR,
                product="assets",
                data_type="assets",
                snapshot_id=snapshot_id,
                items_count=str(total_assets_to_report),
                should_update_health_module=False,
            )

            demisto.updateModuleHealth({"assetsPulled": cumulative_assets_count})

        demisto.setAssetsLastRun(new_last_run)

    elif fetch_stage == "vulnerabilities":
        vulnerabilities, new_last_run = fetch_vulnerabilities(client, last_run)
        demisto.debug(f"Sending {len(vulnerabilities)} vulnerabilities to XSIAM.")
        send_data_to_xsiam(data=vulnerabilities, vendor=VENDOR, product="vulnerabilities", data_type="assets")
        demisto.setAssetsLastRun(new_last_run)

    demisto.debug(f"Finished fetch assets and vulnerabilities run (by date). Last assets run object: {new_last_run}")


def fetch_assets_and_vulnerabilities_by_qids(client: Client, last_run: dict[str, Any]) -> None:
    """
    Fetches host dectections (assets) by VM scan date and vulnerabilities by host detections Qualys IDs (QIDs) in one stage.

    Args:
        client (Client): Qualys client.
        last_run (dict): Last assets run dictionary.
    """
    demisto.debug(f"Starting fetch for assets and vulnerabilities, {EXECUTION_START_TIME=}")

    assets, new_last_run, _, snapshot_id, set_new_limit = fetch_assets(client, last_run)
    detection_qids: list = list({asset.get("DETECTION", {}).get("QID") for asset in assets})
    vulnerabilities, _ = fetch_vulnerabilities(client, last_run, detection_qids) if detection_qids else ([], {})

    # If assets request read timeout (set_new_limit flag is True) or exceeded max exceution time, make next API call smaller
    if set_new_limit or check_fetch_assets_duration_time_exceeded(EXECUTION_START_TIME):
        demisto.debug(
            f"Reducing limit for assets next run due to timeout. Set new limit: {set_new_limit}. "
            f"Elapsed time: {time.time() - EXECUTION_START_TIME}."
        )
        new_last_run = set_assets_last_run_with_new_limit(last_run, last_run.get("limit", HOST_LIMIT))
    else:
        cumulative_assets_count: int = new_last_run["total_assets"]
        has_next_assets_page = bool(new_last_run.get("next_page"))

        cumulative_vulns_count: int = last_run.get("total_vulnerabilities", 0) + len(vulnerabilities)
        new_last_run["total_vulnerabilities"] = cumulative_vulns_count

        demisto.debug(f"Starting to send {len(assets)} assets and {len(vulnerabilities)} vulnerabilities to XSIAM")
        send_assets_and_vulnerabilities_to_xsiam(
            assets=assets,
            vulnerabilities=vulnerabilities,
            cumulative_assets_count=cumulative_assets_count,
            cumulative_vulns_count=cumulative_vulns_count,
            has_next_page=has_next_assets_page,
            snapshot_id=snapshot_id,
        )

        # If no next assets page (i.e. finished fetching assets and their vulnerabilities), then reset last run
        if not has_next_assets_page:
            demisto.debug("Finished fetching all assets and vulnerabilities. Resetting last run object")
            new_last_run = DEFAULT_LAST_ASSETS_RUN

        demisto.updateModuleHealth({"assetsPulled": cumulative_assets_count + cumulative_vulns_count})

    demisto.setAssetsLastRun(new_last_run)
    demisto.debug(f"Finished fetch assets and vulnerabilities run (by QIDs). Last assets run object: {new_last_run}")


""" MAIN FUNCTION """


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    fetch_vulnerabilities_behavior = params["fetch_vulnerabilities_behavior"]

    commands_methods: dict[str, dict[str, Callable]] = {
        # *** Commands with unparsed response as output ***
        "qualys-purge-scan-host-data": {
            "result_handler": handle_general_result,
            "output_builder": build_unparsed_output,
        },
        "qualys-pc-scan-launch": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-pc-scan-manage": {
            "result_handler": handle_general_result,
            "output_builder": build_unparsed_output,
        },
        "qualys-ip-restricted-list": {
            "result_handler": handle_general_result,
            "output_builder": build_ip_list_output,
        },
        "qualys-host-excluded-manage": {
            "result_handler": handle_general_result,
            "output_builder": build_ip_list_from_single_value,
        },
        "qualys-report-template-list": {
            "result_handler": handle_general_result,
            "output_builder": build_unparsed_output,
        },
        "qualys-virtual-host-manage": {
            "result_handler": handle_general_result,
            "output_builder": build_unparsed_output,
        },
        # *** Commands with key value pair as output ***
        "qualys-report-cancel": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-report-delete": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-scorecard-launch": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-scheduled-report-launch": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-report-launch-map": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-report-launch-scan-based-findings": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-report-launch-host-based-findings": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-report-launch-patch": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-report-launch-remediation": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-report-launch-compliance": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-report-launch-compliance-policy": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-asset-group-add": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-asset-group-edit": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-asset-group-delete": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-schedule-scan-create": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-schedule-scan-update": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        "qualys-schedule-scan-delete": {
            "result_handler": handle_general_result,
            "output_builder": build_one_value_parsed_output,
        },
        # *** Commands which need parsing with multiple values ***
        "qualys-report-list": {
            "result_handler": handle_report_list_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-vm-scan-list": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-vm-scan-launch": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-scap-scan-list": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-pc-scan-list": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-schedule-scan-list": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-host-list": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-virtual-host-list": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-vulnerability-list": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-group-list": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-scheduled-report-list": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        "qualys-time-zone-code": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_values_parsed_output,
        },
        # *** Commands with no output ***
        "qualys-report-fetch": {
            "result_handler": handle_fetch_result,
        },
        # *** Commands with a single text as output ***
        "qualys-ip-restricted-manage": {
            "result_handler": handle_general_result,
            "output_builder": build_single_text_output,
        },
        "qualys-ip-add": {
            "result_handler": handle_general_result,
            "output_builder": build_single_text_output,
        },
        "qualys-ip-update": {
            "result_handler": handle_general_result,
            "output_builder": build_single_text_output,
        },
        "qualys-host-update": {
            "result_handler": handle_general_result,
            "output_builder": build_single_text_output,
        },
        "qualys-update-unix-record": {
            "result_handler": handle_general_result,
            "output_builder": build_single_text_output,
        },
        # *** Commands that have lists of ips as outputs ***
        "qualys-ip-list": {
            "result_handler": handle_general_result,
            "output_builder": build_ip_list_output,
        },
        "qualys-host-excluded-list": {
            "result_handler": handle_general_result,
            "output_builder": build_ip_list_output,
        },
        # *** Commands with multiple @value and #text as output ***
        "qualys-pc-scan-fetch": {
            "result_handler": handle_general_result,
            "output_builder": build_text_value_pairs_parsed_output,
        },
        # *** Commands with multiple pre-made text options as output ***
        "qualys-vm-scan-action": {
            "result_handler": handle_general_result,
            "output_builder": build_multiple_text_options_output,
        },
        # *** Commands that need a change of the key names ***
        "qualys-vm-scan-fetch": {
            "result_handler": handle_general_result,
            "output_builder": build_changed_names_output,
        },
        # *** Host List Detection
        "qualys-host-list-detection": {
            "result_handler": handle_general_result,
            "output_builder": build_host_list_detection_outputs,
        },
        # *** Tag related commands ***
        "qualys-asset-tag-list": {
            "result_handler": handle_asset_tag_result,
            "output_builder": build_tag_asset_output,
        },
        "qualys-asset-tag-create": {
            "result_handler": handle_asset_tag_result,
            "output_builder": build_tag_asset_output,
        },
        "qualys-asset-tag-update": {
            "result_handler": handle_asset_tag_result,
            "output_builder": build_tag_asset_output,
        },
        "qualys-asset-tag-delete": {
            "result_handler": handle_asset_tag_result,
            "output_builder": build_tag_asset_output,
        },
        "qualys-update-vmware-record": {
            "result_handler": handle_asset_tag_result,
            "output_builder": build_single_text_output,
        },
        "qualys-update-vcenter-record": {
            "result_handler": handle_asset_tag_result,
            "output_builder": build_single_text_output,
        },
        "qualys-vcenter-esxi-mapped-record-list": {
            "result_handler": handle_general_result,
            "output_builder": build_unparsed_output,
        },
        "qualys-vcenter-esxi-mapped-record-import": {
            "result_handler": handle_asset_tag_result,
            "output_builder": build_single_text_output,
        },
        "qualys-vcenter-esxi-mapped-record-purge": {
            "result_handler": handle_asset_tag_result,
            "output_builder": build_single_text_output,
        },
    }

    demisto.debug(f"Command being called is {command}")
    try:
        headers: dict = {"X-Requested-With": "Cortex"}
        client = Client(
            base_url=base_url, username=username, password=password, verify=verify_certificate, headers=headers, proxy=proxy
        )

        first_fetch_datetime: datetime = arg_to_datetime(  # type: ignore[assignment]
            arg=params.get("first_fetch", "3 days"), arg_name="First fetch time", required=True
        )
        first_fetch_str = first_fetch_datetime.strftime(DATE_FORMAT)

        if command == "test-module":
            text_res = test_module(client, params, first_fetch_str)
            return_results(text_res)

        elif command == "qualys-get-events":
            should_push_events = argToBoolean(args.get("should_push_events", False))
            events, results = get_activity_logs_events_command(client, args, first_fetch_str)
            return_results(results)
            if should_push_events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "qualys-get-assets":
            should_push_events = argToBoolean(args.get("should_push_assets", False))
            since_datetime = arg_to_datetime("1 hour").strftime(ASSETS_DATE_FORMAT)  # type: ignore[union-attr]
            assets, _, _ = get_host_list_detections_events(client=client, since_datetime=since_datetime, limit=1)
            if should_push_events:
                send_data_to_xsiam(data=assets, vendor=VENDOR, product="host_detections", data_type="assets")
            return_results(assets)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            max_fetch_activity_logs = arg_to_number(params.get("max_fetch_activity_logs", 0))
            logs_next_run, activity_logs_events = fetch_events(
                client=client,
                last_run=last_run,
                newest_event_field=ACTIVITY_LOGS_NEWEST_EVENT_DATETIME,
                next_page_field=ACTIVITY_LOGS_NEXT_PAGE,
                previous_run_time_field=ACTIVITY_LOGS_SINCE_DATETIME_PREV_RUN,
                fetch_function=get_activity_logs_events,
                first_fetch_time=first_fetch_str,
                max_fetch=max_fetch_activity_logs,
            )
            send_events_to_xsiam(activity_logs_events, vendor=VENDOR, product=PRODUCT)

            # saves next_run for the time fetch-events is invoked
            demisto.setLastRun(logs_next_run)

        elif command == "fetch-assets":
            last_run = demisto.getAssetsLastRun()

            demisto.debug(f"Fetch vulnerabilites behavior is set to: {fetch_vulnerabilities_behavior}")
            if fetch_vulnerabilities_behavior == "Fetch by unique QIDs of assets":
                fetch_assets_and_vulnerabilities_by_qids(client, last_run)
            else:
                fetch_assets_and_vulnerabilities_by_date(client, last_run)

        elif command in commands_methods:
            return_results(qualys_command_flow_manager(client, args, command, commands_methods[command]))

        else:
            raise NotImplementedError(f"Unknown command {command}")

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
