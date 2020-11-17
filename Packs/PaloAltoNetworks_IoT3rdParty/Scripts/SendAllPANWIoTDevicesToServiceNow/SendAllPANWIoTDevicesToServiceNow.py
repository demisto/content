import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
res = []
run_time_count = 1
offset = 0
PAGE_SIZE = 100
update_num = 0
insert_num = 0
total_update_num = 0
total_insert_num = 0

PANW_IOT_INSTANCE = "PANW IoT 3rd Party Integration Instance"
SERVICENOW_INSTANCE = "PANW IoT 3rd Party ServiceNow Integration Instance"


def send_status_to_panw_iot_cloud(status=None, msg=None):
    demisto.executeCommand("panw-iot-3rd-party-report-status-to-panw", {
        "status": status,
        "message": msg,
        "integration-name": "servicenow",
        "playbook-name": "Bulk Export Devices to ServiceNow - PANW IoT 3rd Party Integration",
        "type": "device",
        "timestamp": int(round(time.time() * 1000)),
        "using": PANW_IOT_INSTANCE
    })


while True:
    # get all devices from the IoT cloud
    resp = demisto.executeCommand("panw-iot-3rd-party-get-asset-list", {
        "assetType": "Device",
        "offset": offset,
        "pageLength": PAGE_SIZE,
        "using": PANW_IOT_INSTANCE
    })
    if isError(resp[0]):

        err_msg = "Error, could not get Devices from Iot Cloud %s" % resp[0]
        send_status_to_panw_iot_cloud("error", err_msg)
        demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % err_msg)
        return_error("Error, could not get devices from Iot Cloud")
        break
    size = 0

    try:
        device_list = resp[0]['Contents']
        size = len(device_list)
        deviceid_list = [device['deviceid'] for device in device_list]
        query = "mac_addressIN" + ",".join(deviceid_list)
        sn_query_resp = demisto.executeCommand("servicenow-query-table", {
            "table_name": "u_zingbox_discovered_devices",
            "limit": 10000,
            "query": query,
            "fields": "sys_id,mac_address",
            "using": SERVICENOW_INSTANCE
        })

        sn_query_result = sn_query_resp[0]['Contents']['result']
        if len(sn_query_result) > 0:
            upsert_devices_resp = demisto.executeCommand("panw-iot-3rd-party-convert-assets-to-external-format", {
                "assetType": "Device",
                "outputFormat": "ServiceNow",
                "metadata": sn_query_result,
                "assetList": device_list,
                "using": PANW_IOT_INSTANCE
            })
            upsert_devices_result = upsert_devices_resp[0]["Contents"]

            insert_count = upsert_devices_result['insert_count']
            update_count = upsert_devices_result['update_count']
            total_update_num += update_count
            total_insert_num += insert_count
            update_num = update_count
            insert_num = insert_count

            if insert_count == 0 and update_count == 0:
                err_msg = "Error, Bulk Servicenow sync failed to get upsert devices from PANW IoT cloud %s" % upsert_devices_result
                send_status_to_panw_iot_cloud("error", err_msg)
                demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % err_msg)
                return_error("Error, could not get upsert devices")
            if insert_count > 0:
                insert_list = upsert_devices_result['insert']
                for x in range(len(insert_list)):
                    device = insert_list[x]
                    fields = device['fields']
                    custom_fields = device['custom_fields']
                    demisto.executeCommand("servicenow-create-record", {
                        "table_name": "u_zingbox_discovered_devices",
                        "fields": fields,
                        "custom_fields": custom_fields,
                        "using": SERVICENOW_INSTANCE
                    })
            if update_count > 0:
                update_list = upsert_devices_result['update']
                for x in range(len(update_list)):
                    device = update_list[x]
                    fields = device['fields']
                    custom_fields = device['custom_fields']
                    sys_id = device['sys_id']
                    demisto.executeCommand("servicenow-update-record", {
                        "table_name": "u_zingbox_discovered_devices",
                        "fields": fields,
                        "custom_fields": custom_fields,
                        "id": sys_id,
                        "using": SERVICENOW_INSTANCE
                    })

    except Exception as ex:
        demisto.results("Failed to export device to ServiceNow %s" % str(ex))
        return_error(str(ex))

    if size == PAGE_SIZE:
        offset += PAGE_SIZE
        msg = str(run_time_count) + ". Successfully update " + str(update_num) + \
            " Devices and insert " + str(insert_num) + " to Servicenow "
        send_status_to_panw_iot_cloud("success", msg)
        demisto.results(str(run_time_count) + ".Successfully update " + str(update_num) +
                        " Devices and insert " + str(insert_num) + " to Servicenow")
        run_time_count += 1
    else:
        break

msg = "Successfully total update " + \
    str(total_update_num) + " Devices to Servicenow and total insert " + str(total_insert_num) + " Devices to Servicenow"
send_status_to_panw_iot_cloud("success", msg)
demisto.results("Successfully total update " + str(total_update_num) +
                " Devices to Servicenow and total insert " + str(total_insert_num) + " Devices to Servicenow")
