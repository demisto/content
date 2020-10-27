import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
count = 0
res = []
offset = 0
PAGE_SIZE = 1000

while True:
    resp = demisto.executeCommand("get-asset-inventory-with-paging-and-offset", {
        "page_size": PAGE_SIZE,
        "offset": offset,
        "type": "Alerts",
        "using": "Palo Alto IoT Third-Party-Integration Base Instance"
    })
    if isError(resp[0]):
        demisto.executeCommand("send-status-to-panw-iot-cloud", {
            "status": "error",
            "message": "Error, could not get Alerts from Iot Cloud",
            "integration-name": "SIEM",
            "playbook-name": "panw_iot_siem_bulk_integration",
            "type": "alert",
            "timestamp": int(round(time.time() * 1000)),
            "using": "Palo Alto IoT Third-Party-Integration Base Instance"
        })
        return_error("Error, could not get Alerts from Iot Cloud")
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

                demisto.executeCommand("syslog-send", {"message": cef, "using": "PANW IoT Siem Instance"})
                count += 1

    except Exception as ex:
        demisto.results("Failed to parse alert map %s" % str(ex))

    if size == PAGE_SIZE:
        offset += PAGE_SIZE
        demisto.executeCommand("send-status-to-panw-iot-cloud", {
            "status": "success",
            "message": "Successfully sent %d Alerts to SIEM" % count,
            "integration-name": "SIEM",
            "playbook-name": "panw_iot_siem_bulk_integration",
            "type": "alert",
            "timestamp": int(round(time.time() * 1000)),
            "using": "Palo Alto IoT Third-Party-Integration Base Instance"
        })
        demisto.results("Successfully sent %d Alert to SIEM" % count)
        time.sleep(3)
    else:
        break

demisto.executeCommand("send-status-to-panw-iot-cloud", {
    "status": "success",
    "message": "Successfully sent total %d Alerts to SIEM" % count,
    "integration-name": "SIEM",
    "playbook-name": "panw_iot_siem_bulk_integration",
    "type": "alert",
    "timestamp": int(round(time.time() * 1000)),
    "using": "Palo Alto IoT Third-Party-Integration Base Instance"
})
demisto.results("Successfully sent total %d Alerts to SIEM" % count)
