import demistomock as demisto
from CommonServerPython import *
SIEM_INSTANCE = demisto.args().get('syslog_sender_instance')
PANW_IOT_INSTANCE = demisto.args().get('panw_iot_3rd_party_instance')


def send_status_to_panw_iot_cloud(status, msg, asset_type):
    """
    Reports status details back to PANW IoT Cloud.
    param status: Status (error, disabled, success) to be send to PANW IoT cloud.
    param msg: Debug message to be send to PANW IoT cloud.
    param asset_type: Type of asset (device, alert, vuln) associated with the status.
    """
    resp = demisto.executeCommand("panw-iot-3rd-party-report-status-to-panw", {
        "status": status,
        "message": msg,
        "integration_name": "siem",
        "playbook_name": "PANW IoT 3rd Party SIEM Integration - Bulk Export to SIEM",
        "asset_type": asset_type,
        "timestamp": int(round(time.time() * 1000)),
        "using": PANW_IOT_INSTANCE
    })

    if isError(resp[0]):
        err_msg = f'Error, failed to send status to PANW IoT Cloud - {resp[0].get("Contents")}'
        raise Exception(err_msg)


def get_assets_from_panw_iot_cloud(offset, page_size, asset_type):
    """
    Gets assets from PANW IoT cloud.
    param offset: Offset number for the asset list.
    param page_size: Page size of the response being requested.
    param asset_type: Type of asset (device, alert, vuln) to be retrieved.
    """
    resp = demisto.executeCommand("panw-iot-3rd-party-get-asset-list", {
        "asset_type": asset_type,
        "increment_type": None,
        "offset": offset,
        "pageLength": page_size,
        "using": PANW_IOT_INSTANCE

    })
    if isError(resp[0]):
        err_msg = f'Error, could not get assets from PANW IoT Cloud - {resp[0].get("Contents")}'
        raise Exception(err_msg)

    return resp[0]['Contents']


def convert_asset_to_cef_format(asset_list, asset_type):
    """
    Converts a list of assets to CEF syslog format.
    param asset_list: The list of assets to be converted.
    param asset_type: Type of asset (device, alert, vuln).
    """
    resp = demisto.executeCommand("panw-iot-3rd-party-convert-assets-to-external-format", {
        "asset_type": asset_type,
        "output_format": "SIEM",
        "asset_list": asset_list,
        "using": PANW_IOT_INSTANCE
    })
    if isError(resp[0]):
        err_msg = f'Error, failed to convert PANW IoT assets to external format - {resp[0].get("Contents")}'
        raise Exception(err_msg)

    return resp[0]['Contents']


def send_asset_syslog(cef):
    """
    Sends the cef formated message as syslogs.
    param cef: The cef formated message to be sent as syslog.
    """
    res = demisto.executeCommand("syslog-send", {"message": cef, "using": SIEM_INSTANCE})
    if isError(res[0]):
        # We only get an error if configured syslog server address cant be resolved
        err_msg = f'Cant connect to SIEM server - {res[0].get("Contents")}'
        raise Exception(err_msg)


def get_all_panw_iot_assets_and_send_to_siem(asset_type):
    """
    Retrieves all assets from PANW IoT Cloud, 1000 assets at a time and sends it
    to the syslog server.
    param asset_type: Type of asset (device, alert, vuln).
    """
    count = 0
    offset = 0
    page_size = 1000
    if asset_type is None:
        raise TypeError("Invalid asset type. Asset type passed is null")
    asset_type_map = {"device": "Devices", "alert": "Alerts", "vulnerability": "Vulnerabilities"}

    while True:
        asset_list = get_assets_from_panw_iot_cloud(offset, page_size, asset_type)
        size = len(asset_list)
        cef_list = convert_asset_to_cef_format(asset_list, asset_type)
        for cef in cef_list:
            send_asset_syslog(cef)
            count += 1
        if size >= page_size:
            offset += page_size
        else:
            break
    return(f'Successfully sent total {count} {asset_type_map[asset_type]} to SIEM')


def main():
    asset_type = demisto.args().get('asset_type')
    try:
        status_msg = get_all_panw_iot_assets_and_send_to_siem(asset_type)
    except Exception as ex:
        send_status_to_panw_iot_cloud("error", str(ex), asset_type)
        return_error(str(ex))

    send_status_to_panw_iot_cloud("success", status_msg, asset_type)
    return_results(status_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
