import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

PANW_IOT_INSTANCE = demisto.args().get('panw_iot_3rd_party_instance')
CISCO_ISE_ACTIVE_INSTANCE = demisto.args().get("active_ise_instance")
GET_EP_ID_CMD = 'cisco-ise-get-endpoint-id-by-name'


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
    global GET_EP_ID_CMD

    cmd_mac_syntax_map = {
        "cisco-ise-get-endpoint-id-by-name": "mac_address",
        "cisco-ise-get-endpoint-id": "macAddress"
    }

    # Check if this mac address (endpoint) is present in ISE by attempting to get its ID
    resp = demisto.executeCommand(GET_EP_ID_CMD, {
        cmd_mac_syntax_map[GET_EP_ID_CMD]: mac,
        "using": CISCO_ISE_ACTIVE_INSTANCE
    })

    if isError(resp[0]):
        err_msg = extract_ise_api_error(resp[0].get("Contents"))

        # 404 Not Found or empty results, we need to create a new EP
        if err_msg == "404" or err_msg == "list index out of range":
            create_new_ep(mac, attr_map, CISCO_ISE_ACTIVE_INSTANCE)

        # 405 - Method not allowed means we need to switch to an old filter based API
        elif err_msg == '405':
            GET_EP_ID_CMD = "cisco-ise-get-endpoint-id"

        else:
            raise Exception(resp[0].get("Contents"))
    else:
        ep_id = resp[0]['EntryContext']['Endpoint(val.ID === obj.ID)']['ID']
        update_existing_endpoint(mac, attr_map, ep_id, CISCO_ISE_ACTIVE_INSTANCE)


def send_panw_iot_devices_to_send_to_cisco_ise(device_list):
    """
    For given device lists consisting of custom attributes, create or update
    endpoints in Cisco ISE.
    Param device_list: a list of devices and their custom attributes.
    """
    count = 0
    for device in device_list:
        mac = device['mac']
        attr_map = device['zb_attributes']
        create_or_update_ep(mac, attr_map)
        count += 1

    return f'Successfully exported {count} devices to Cisco ISE'


def main():
    device_list = demisto.args().get('device_maps')
    status_msg = None
    try:
        status_msg = send_panw_iot_devices_to_send_to_cisco_ise(device_list)
    except Exception as ex:
        send_status_to_panw_iot_cloud("error", str(ex))
        return_error(str(ex))

    send_status_to_panw_iot_cloud("success", status_msg)
    return_results(
        CommandResults(
            readable_output=status_msg,
            outputs_prefix="PaloAltoIoTIntegrationBase.Status",
            outputs=status_msg
        )
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
