import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

PANW_IOT_INSTANCE = demisto.args().get('panw_iot_3rd_party_instance')
CISCO_ISE_ACTIVE_INSTANCE = demisto.args().get("active_ise_instance")


def send_status_to_panw_iot_cloud(status, msg):
    """
    Reports status details back to PANW IoT Cloud.
    param status: Status (error, disabled, success) to be send to PANW IoT cloud.
    param msg: Debug message to be send to PANW IoT cloud.
    """
    resp = demisto.executeCommand("panw-iot-3rd-party-report-status-to-panw", {
        "status": status,
        "message": msg,
        "integration_name": "ise",
        "playbook_name": "PANW IoT 3rd Party Cisco ISE Integration - Bulk Export to Cisco ISE",
        "asset_type": 'device',
        "timestamp": int(round(time.time() * 1000)),
        "using": PANW_IOT_INSTANCE
    })

    if isError(resp[0]):
        err_msg = f'Error, failed to send status to PANW IoT Cloud - {resp[0].get("Contents")}'
        raise Exception(err_msg)


def get_active_ise_instance_or_error_msg():
    """
    Get the active configured Cisco ISE instance, if not found then return the error message.
    """
    response = demisto.executeCommand("GetCiscoISEActiveInstance", {})
    err_msg = None
    active_instance = None

    data = response[0].get('EntryContext', {})

    if 'PaloAltoIoTIntegrationBase.ActiveNodeInstance' in data:
        active_instance = data.get('PaloAltoIoTIntegrationBase.ActiveNodeInstance')
    elif 'PaloAltoIoTIntegrationBase.NodeErrorStatus' in data:
        err_msg = data.get('PaloAltoIoTIntegrationBase.NodeErrorStatus')

    return active_instance, err_msg


def extract_ise_api_error(err_msg):
    """
    Extract any connection error or error code if possible,
    Otherwise just return the original error
    """
    err_msg = err_msg.split('-')[0]
    if err_msg.startswith("Error in API call to Cisco"):
        start = err_msg.find('[') + 1
        end = err_msg.find(']')
        return err_msg[start:end]
    elif err_msg.startswith("Connection Error. Verify"):
        return "Connection Error"
    else:
        return err_msg


def get_devices_from_panw_iot_cloud(offset, page_size):
    """
    Gets assets from PANW IoT cloud.
    param offset: Offset number for the asset list.
    param page_size: Page size of the response being requested.
    """
    resp = demisto.executeCommand("panw-iot-3rd-party-get-asset-list", {
        "asset_type": 'device',
        "increment_type": None,
        "offset": offset,
        "pageLength": page_size,
        "using": PANW_IOT_INSTANCE

    })
    if isError(resp[0]):
        err_msg = f'Error, could not get assets from PANW IoT Cloud - {resp[0].get("Contents")}'
        raise Exception(err_msg)

    return resp[0]['Contents']


def convert_device_list_to_cisco_ise_custom_attributes(device_list):
    """
    Converts a list of PANW IoT devices to Cisco ISE custom attributes maps.
    param device_list: The list of PANW IoT devices to be converted.
    """
    resp = demisto.executeCommand("panw-iot-3rd-party-convert-assets-to-external-format", {
        "asset_type": 'device',
        "output_format": "CiscoISECustomAttributes",
        "asset_list": device_list,
        "using": PANW_IOT_INSTANCE
    })
    if isError(resp[0]):
        err_msg = f'Error, failed to convert PANW IoT devices to CiscoISECustomAttributes- {resp[0].get("Contents")}'
        raise Exception(err_msg)

    return resp[0]['Contents']


def update_existing_endpoint(mac, attr_map, ep_id, active_instance):
    """
    Update an existing endpoint with the given custom attributes.
    Param mac: mac address of the endpoint that needs to be updated.
    Param attr_map: a map containing various ise custom attributes.
    Param ep_id: ID for endpoint that needs to be updated.
    Param active_instance: The primary/active ISE instance.
    """
    attribute_names = ""
    attribute_values = ""
    for key in attr_map:
        attribute_names += key + ","
        attribute_values += str(attr_map[key]) + ","
    attribute_names = attribute_names[:-1]
    attribute_values = attribute_values[:-1]

    resp = demisto.executeCommand("cisco-ise-update-endpoint-custom-attribute", {
        "id": ep_id,
        "macAddress": mac,
        "attributeName": attribute_names,
        "attributeValue": attribute_values,
        "using": active_instance
    })
    if isError(resp[0]):
        err_msg = f'Error, failed to update custom attributes for endpoint {id} - {resp[0].get("Contents")}'
        raise Exception(err_msg)


def create_new_ep(mac, attr_map, active_instance):
    """
    Create a new endpoint with the given params
    Param mac: mac address of the endpoint that needs to be created.
    Param attr_map: a map containing various ise custom attributes.
    Param active_instance: The primary/active ISE instance.
    """
    resp = demisto.executeCommand("cisco-ise-create-endpoint", {
        "mac_address": mac,
        "attributes_map": attr_map,
        "using": active_instance
    })
    if isError(resp[0]):
        err_msg = f'Failed to create new Endpoint {mac} - {resp[0].get("Contents")}'
        raise Exception(err_msg)


def create_or_update_ep(mac, attr_map):
    """
    Check if an enpoint exists in ISE, if not create one with the custom attributes
    otherwise update it. If at any point the connection goes down or we get a 401 -
    unautherized access we will attempt to get the new active instance.
    Params mac: Mac adress of the endpoint.
    attr_map: Custom attributes for the endpoint.
    """

    global CISCO_ISE_ACTIVE_INSTANCE
    get_ep_id_cmd = "cisco-ise-get-endpoint-id-by-name"
    cmd_mac_syntax_map = {
        "cisco-ise-get-endpoint-id-by-name": "mac_address",
        "cisco-ise-get-endpoint-id": "macAddress"
    }

    # Check if this mac address (endpoint) is present in ISE by attempting to get its ID
    resp = demisto.executeCommand(get_ep_id_cmd, {
        cmd_mac_syntax_map[get_ep_id_cmd]: mac,
        "using": CISCO_ISE_ACTIVE_INSTANCE
    })

    if isError(resp[0]):
        err_msg = extract_ise_api_error(resp[0].get("Contents"))

        # 404 Not Found or empty results, we need to create a new EP
        if err_msg == "404" or err_msg == "list index out of range":
            create_new_ep(mac, attr_map, CISCO_ISE_ACTIVE_INSTANCE)

        # 405 - Method not allowed means we need to switch to an old filter based API
        elif err_msg == '405':
            get_ep_id_cmd = "cisco-ise-get-endpoint-id"

        # The primary went down (connection Error) or 401 if a fail over occurred (this primary/active
        # is not a secondary/standby device).We should attempt to get the new Primary/Active
        # instance is possible.
        elif err_msg == "Connection Error" or err_msg == "401":
            # Failover can take up to 10 minutes, its ok to just wait even if its a standalone ISE noe.
            msg = "ISE instance is down. Trying again in 10 minutes. Error = %s" % err_msg
            demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % msg)
            send_status_to_panw_iot_cloud("error", msg)
            time.sleep(10 * 60)
            # Try again to get a new active instance
            new_active_instance, err_msg = get_active_ise_instance()
            if new_active_instance is None:
                raise Exception(err_msg)
            else:
                CISCO_ISE_ACTIVE_INSTANCE = new_active_instance
                msg = "Found new active ISE instance %s" % CISCO_ISE_ACTIVE_INSTANCE
                send_status_to_panw_iot_cloud("success", msg)
        else:
            raise Exception(resp[0].get("Contents"))
    else:
        ep_id = resp[0]['EntryContext']['Endpoint(val.ID === obj.ID)']['ID']
        update_existing_endpoint(mac, attr_map, ep_id, CISCO_ISE_ACTIVE_INSTANCE)


def get_all_panw_iot_devices_and_send_to_cisco_ise():
    """
    Retrieves all devices from PANW IoT Cloud, 1000 devices at a time and sends it
    to the primary/active cisco ise.
    """
    count = 0
    offset = 0
    page_size = 1000

    while True:
        device_list = get_devices_from_panw_iot_cloud(offset, page_size)
        size = len(device_list)
        custom_attributes_list = convert_device_list_to_cisco_ise_custom_attributes(device_list)
        for entry in custom_attributes_list:
            mac = entry['mac']
            attr_map = entry['zb_attributes']
            create_or_update_ep(mac, attr_map)
            count += 1
            # time.sleep(1)

        if size == page_size:
            offset += page_size
            msg = f'Successfully exported {count} devices to Cisco ISE'
            send_status_to_panw_iot_cloud("success", msg,)
            # time.sleep(5)
        else:
            break
    return(f'Successfully exported total {count} devices to Cisco ISE')


def main():
    try:
        status_msg = get_all_panw_iot_devices_and_send_to_cisco_ise()
    except Exception as ex:
        send_status_to_panw_iot_cloud("error", str(ex))
        return_error(str(ex))

    send_status_to_panw_iot_cloud("success", status_msg)
    return_results(status_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
