import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
count = 0
res = []
offset = 0
PAGE_SIZE = 1000

SIEM_INSTANCE = "PANW IoT 3rd Party SIEM Integration Instance"
PANW_IOT_INSTANCE = "PANW IoT 3rd Party Integration Instance"

'''
returns a status and message back to cloud
'''


def send_status_to_panw_iot_cloud(status=None, msg=None):
    demisto.executeCommand("panw-iot-3rd-party-report-status-to-panw", {
        "status": status,
        "message": msg,
        "integration-name": "siem",
        "playbook-name": "PANW IoT 3rd Party SIEM Integration - Bulk Export to SIEM",
        "type": "alert",
        "timestamp": int(round(time.time() * 1000)),
        "using": PANW_IOT_INSTANCE
    })


while True:
    resp = demisto.executeCommand("panw-iot-3rd-party-get-asset-list", {
        "assetType": "Alert",
        "incrementTime": None,
        "offset": offset,
        "pageLength": PAGE_SIZE,
        "using": PANW_IOT_INSTANCE

    })
    if isError(resp[0]):
        err_msg = "Error, could not get alerts from Iot Cloud %s" % resp[0].get('Contents')
        send_status_to_panw_iot_cloud("error", err_msg)
        demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % err_msg)
        return_error(err_msg)
        break
    size = 0
    try:
        alert_list = resp[0]['Contents']
        size = len(alert_list)
        for alert in alert_list:
            if alert != None and "msg" in alert and "status" in alert["msg"] and alert["msg"]["status"] == "publish":
                msg = alert['msg']
                cef = "CEF:0|PaloAltoNetworks|PANWIOT|1.0|PaloAltoNetworks Alert:policy_alert|"

                if "name" in alert:
                    cef += alert["name"] + "|"
                if "severityNumber" in alert:
                    cef += str(alert["severityNumber"]) + "|"
                if "deviceid" in alert:
                    cef += "dvcmac=%s " % alert["deviceid"]
                if "fromip" in msg:
                    cef += "src=%s " % msg["fromip"]
                if "toip" in msg:
                    cef += "dst=%s " % msg["toip"]
                if "hostname" in msg:
                    cef += "shost=%s " % msg["hostname"]
                if "toURL" in msg:
                    cef += "dhost=%s " % msg["toURL"]
                if "id" in msg:
                    cef += "fileId=%s " % msg["id"]
                    cef += "fileType=alert "

                if "date" in alert:
                    cef += "rt=%s " % str(msg["id"])
                if "generationTimestamp" in msg:
                    cef += "deviceCustomDate1=%s " % str(msg["generationTimestamp"])

                description = None
                values = []
                if "description" in alert:
                    description = alert["description"]
                if "values" in msg:
                    values = msg["values"]

                cef += "cs1Label=Description cs1=%s " % description
                cef += "cs2Label=Values cs2=%s " % str(values)

                res = demisto.executeCommand("syslog-send", {"message": cef, "using": SIEM_INSTANCE})
                if isError(res[0]):
                    # We only get an error is configured syslog server address cant be resolved
                    err_msg = "Cant connect to SIEM server %s" % res[0].get('Contents')
                    send_status_to_panw_iot_cloud("error", err_msg)
                    return_error(err_msg)
                else:
                    count += 1

    except Exception as ex:
        return_error("Failed to parse alert map %s" % str(ex))

    if size == PAGE_SIZE:
        offset += PAGE_SIZE
        msg = "Successfully sent %d Alerts to SIEM" % count
        send_status_to_panw_iot_cloud("success", msg)
        demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % msg)
        time.sleep(5)
    else:
        break

msg = "Successfully sent total %d Alerts to SIEM" % count
send_status_to_panw_iot_cloud("success", msg)
demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % msg)
return_results(msg)
