import demistomock as demisto
from CommonServerPython import *
PANW_IOT_INSTANCE = "PANW IoT 3rd Party Integration Instance"
SERVICENOW_INSTANCE = "PANW IoT 3rd Party ServiceNow Integration Instance"
PAGE_SIZE = 100
SERVICENOW_TABLE_NAME = "u_zingbox_discovered_devices"


def send_status_to_panw_iot_cloud(status=None, msg=None):
    """
    To send error/success status back to PANW IoT cloud
    :param status: status needs to send back
    :param msg: message
    """
    resp = demisto.executeCommand("panw-iot-3rd-party-report-status-to-panw", {
        "status": status,
        "message": msg,
        "integration_name": "servicenow",
        "playbook_name": "Bulk Export Devices to ServiceNow - PANW IoT 3rd Party Integration",
        "asset_type": "device",
        "timestamp": int(round(time.time() * 1000)),
        "using": PANW_IOT_INSTANCE
    })
    if isError(resp[0]):
        err_msg = f'Error, failed to send status to PANW IoT Cloud - {resp[0].get("Contents")}'
        raise Exception(err_msg)


def get_devices_from_panw_iot_cloud(offset):
    """
    To retrieve a list of devices list from PANW IoT cloud controled by offset and PAGE_SIZE
    :param offset: The index from DB to return the results.
    :return: list of device
    """
    resp = demisto.executeCommand("panw-iot-3rd-party-get-asset-list", {
        "asset_type": "device",
        "offset": offset,
        "page_length": PAGE_SIZE,
        "using": PANW_IOT_INSTANCE
    })
    if isError(resp[0]):
        err_msg = f'Error, could not get assets from PANW IoT Cloud - {resp[0].get("Contents")}'
        raise Exception(err_msg)

    return resp[0]['Contents']


def query_servicenow_table(query):
    """
    To query Servicenow table to get a deviceid and Servicenow table row id map
    :param query: Servicenow table query with device information
    :return: the deviceid and Servicenow table row id map
    """
    sn_query_resp = demisto.executeCommand("servicenow-query-table", {
        "table_name": SERVICENOW_TABLE_NAME,
        "limit": 10000,
        "query": query,
        "fields": "sys_id,mac_address",
        "using": SERVICENOW_INSTANCE
    })
    return sn_query_resp[0]['Contents']['result']


def get_servicenow_upsert_device_list(sn_query_result, device_list):
    """
    To get Upsert device json object
    :param sn_query_result: the deviceid and Servicenow table row id map
    :param device_list: list of device
    :return: upsert device json object
    """
    upsert_devices_resp = demisto.executeCommand("panw-iot-3rd-party-convert-assets-to-external-format", {
        "asset_type": "device",
        "output_format": "ServiceNow",
        "servicenow_map": sn_query_result,
        "asset_list": device_list,
        "using": PANW_IOT_INSTANCE
    })
    return upsert_devices_resp[0]["Contents"]


def create_servicenow_record(insert_list):
    """
    To create Servicenow record
    :param insert_list: device list that needs to insert into Servicenow table
    """
    for x in range(len(insert_list)):
        device = insert_list[x]
        fields = device['fields']
        custom_fields = device['custom_fields']
        demisto.executeCommand("servicenow-create-record", {
            "table_name": SERVICENOW_TABLE_NAME,
            "fields": fields,
            "custom_fields": custom_fields,
            "using": SERVICENOW_INSTANCE
        })


def update_servicenow_record(update_list):
    """
    To update existing device record in Servicenow
    :param update_list: device list that needs to be updated
    """
    for x in range(len(update_list)):
        device = update_list[x]
        fields = device['fields']
        custom_fields = device['custom_fields']
        sys_id = device['sys_id']
        demisto.executeCommand("servicenow-update-record", {
            "table_name": SERVICENOW_TABLE_NAME,
            "fields": fields,
            "custom_fields": custom_fields,
            "id": sys_id,
            "using": SERVICENOW_INSTANCE
        })


def get_all_panw_iot_devices_and_send_to_servicenow():
    """
    To send all devices from PANW IoT cloud to Servicenow
    :return: A summary message
    """
    run_time_count = 1
    offset = 0
    update_num = 0
    insert_num = 0
    total_update_num = 0
    total_insert_num = 0
    while True:
        size = 0
        device_list = get_devices_from_panw_iot_cloud(offset)
        size = len(device_list)
        deviceid_list = [device['deviceid'] for device in device_list]
        query = "mac_addressIN" + ",".join(deviceid_list)
        sn_query_result = query_servicenow_table(query)

        if len(sn_query_result) > 0:
            upsert_devices_result = get_servicenow_upsert_device_list(sn_query_result, device_list)
            insert_count = upsert_devices_result['insert_count']
            update_count = upsert_devices_result['update_count']
            total_update_num += update_count
            total_insert_num += insert_count
            update_num = update_count
            insert_num = insert_count
            if insert_count == 0 and update_count == 0:
                err_msg = (
                    f'Error, Bulk Servicenow sync failed to get upsert '
                    f'devices from PANW IoT cloud {upsert_devices_result}'
                )
                send_status_to_panw_iot_cloud("error", err_msg)
                LOG(f'{PANW_IOT_INSTANCE} {err_msg}')
                raise Exception(err_msg)
            if insert_count > 0:
                insert_list = upsert_devices_result['insert']
                create_servicenow_record(insert_list)
            if update_count > 0:
                update_list = upsert_devices_result['update']
                update_servicenow_record(update_list)
        if size == PAGE_SIZE:
            offset += PAGE_SIZE
            msg = (
                f'{str(run_time_count)}. Successfully update {str(update_num)}'
                f' Devices and insert {str(insert_num)} to Servicenow'
            )
            send_status_to_panw_iot_cloud("success", msg)
            run_time_count += 1
        else:
            break
    summary_msg = (
        f'Successfully total update {str(total_update_num)} devices to Servicenow and '
        f'total insert {str(total_insert_num)} devices to Servicenow'
    )
    return summary_msg


def main():
    summary_msg = ""
    try:
        summary_msg = get_all_panw_iot_devices_and_send_to_servicenow()
    except Exception as ex:
        send_status_to_panw_iot_cloud("error", str(ex))
        return_error(str(ex))
    send_status_to_panw_iot_cloud("success", summary_msg)
    return_results(summary_msg)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
