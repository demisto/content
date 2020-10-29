import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


res = []
count = 0
offset = 0
PAGE_SIZE = 1000
update_num = 0
insert_num = 0
while True:
    # get all devices from the IoT cloud
    resp = demisto.executeCommand("get-asset-inventory-with-paging-and-offset", {
        "page_size": PAGE_SIZE,
        "offset": offset,
        "type": "Devices",
        "using": "Palo Alto IoT Third-Party-Integration Base Instance"
    })
    if isError(resp[0]):
        # figure out how to get the error message from the previous command to pass along
        demisto.executeCommand("send-status-to-panw-iot-cloud", {
            "status": "error",
            "message": "Error, could not get devices from Iot Cloud",
            "integration-name": "servicenow",
            "playbook-name": "panw_iot_servicenow_bulk_integration",
            "type": "device",
            "timestamp": int(round(time.time() * 1000)),
            "using": "Palo Alto IoT Third-Party-Integration Base Instance"
        })
        return_error("Error, could not get devices from Iot Cloud")
    size = 0
    try:
        device_list = resp[0]['Contents']
        size = len(device_list)
        query_resp = demisto.executeCommand("get-servicenow-device-query", {
            "devices": device_list,
            "using": "Palo Alto IoT Third-Party-Integration Base Instance"
        })
        query = query_resp[0]['Contents']['query']
        sn_query_resp = demisto.executeCommand("servicenow-query-table", {
            "table_name": "u_zingbox_discovered_devices",
            "limit": 10000,
            "query": query,
            "fields": "sys_id,mac_address"
        })

        sn_query_result = sn_query_resp[0]['Contents']['result']

        if len(sn_query_result) > 0:
            upsert_devices_resp = demisto.executeCommand("get-servicenow-upsert-devices", {
                "devices": device_list,
                "sn_id_deviceids": sn_query_result,
                "using": "Palo Alto IoT Third-Party-Integration Base Instance"
            })
            upsert_devices_result = upsert_devices_resp[0]["Contents"]

            insert_count = upsert_devices_result['insert_count']
            update_count = upsert_devices_result['update_count']
            update_num += update_count
            insert_num += insert_count

            if insert_count == 0 and update_count == 0:
                demisto.executeCommand("send-status-to-panw-iot-cloud", {
                    "status": "error",
                    "message": "Bulk Servicenow sync failed to get upsert devices from PANW IoT cloud",
                    "integration-name": "servicenow",
                    "playbook-name": "panw_iot_servicenow_bulk_integration",
                    "type": "device",
                    "timestamp": int(round(time.time() * 1000)),
                    "using": "Palo Alto IoT Third-Party-Integration Base Instance"
                })
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
                        "custom_fields": custom_fields
                    })
            if update_count > 0:
                update_list = upsert_devices_result['update']
                for x in range(len(update_list)):
                    device = update_list[x]
                    fields = device['fields']
                    custom_fields = device['custom_fields']
                    sys_id = device['sys_id']
                    demisto.executeCommand("servicenow-create-record", {
                        "table_name": "u_zingbox_discovered_devices",
                        "fields": fields,
                        "custom_fields": custom_fields,
                        "id": sys_id
                    })

    except Exception as ex:
        demisto.results("Failed to parse device map %s" % str(ex))

    if size == PAGE_SIZE:
        offset += PAGE_SIZE
        demisto.executeCommand("send-status-to-panw-iot-cloud", {
            "status": "success",
            "message": "Successfully sent %d Devices to Servicenow" % count,
            "integration-name": "servicenow",
            "playbook-name": "panw_iot_servicenow_bulk_integration",
            "type": "device",
            "timestamp": int(round(time.time() * 1000)),
            "using": "Palo Alto IoT Third-Party-Integration Base Instance"
        })
        demisto.results("Successfully sent %d Devices to Servicenow" % count)
        time.sleep(5)
    else:
        break

demisto.executeCommand("send-status-to-panw-iot-cloud", {
    "status": "success",
    "message": "Successfully update " + str(update_num) + " Devices to Servicenow and insert " + str(insert_num) + " Devices to Servicenow",
    "integration-name": "servicenow",
    "playbook-name": "panw_iot_servicenow_bulk_integration",
    "type": "device",
    "timestamp": int(round(time.time() * 1000)),
    "using": "Palo Alto IoT Third-Party-Integration Base Instance"
})
demisto.results("Successfully update " + str(update_num) +
                " Devices to Servicenow and insert " + str(insert_num) + " Devices to Servicenow")
