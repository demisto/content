import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

API_ENDPOINT_URL = "/public_api/v1/audits/management_logs"

def main():

    args = demisto.args()
    list_name_log_count = args.get('AuditLogCountList')
    instance_name = args.get('CoreRestInstanceName')
    splunk_instance_name = args.get('SplunkInstanceName')

    # Get offset
    last_fetched_index = demisto.executeCommand("getList", {
        "listName": list_name_log_count
    })[0]['Contents']

    last_fetched_index = int(last_fetched_index) if last_fetched_index else 0

    body = {
        "request_data": {
            "search_from": last_fetched_index+1,
            "search_to": last_fetched_index+100,
            "sort": {
            "field": "timestamp",
            "keyword": "asc"
            }
        }
    }

    # Get audit logs
    all_audit_logs = demisto.dt(demisto.executeCommand("core-api-post", {
        "uri": API_ENDPOINT_URL,
        "body": body,
        "using": instance_name
    }), "Contents.response.reply.data")

    if all_audit_logs:
        # Get number of logs pulled
        total_logs = len(all_audit_logs)

        # Submit each log as an even to HEC
        for log in all_audit_logs:
            submit_event = demisto.executeCommand("splunk-submit-event-hec", {
                "event": log,
                "using": splunk_instance_name
            })
            if 'sent successfully' not in submit_event:
                return_error(submit_event[0]['Contents'])
                sys.exit(1)

    else:
        return_results("No Logs Found")

    # Update the new offset
    demisto.executeCommand("setList", {
        "listName": list_name_log_count,
        "listData": last_fetched_index+total_logs
    })


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()



