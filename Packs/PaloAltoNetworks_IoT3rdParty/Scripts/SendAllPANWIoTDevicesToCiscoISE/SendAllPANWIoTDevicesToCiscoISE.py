import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
cisco_ise_field_map = {
    "ip": ["ZingboxIpAddress", "PanwIoTIpAddress"],
    "ip address": ["ZingboxIP", "PanwIoTIP"],
    "ip_address": ["ZingboxIP", "PanwIoTIP"],
    "profile": ["ZingboxProfile", "PanwIoTProfile"],
    "category": ["ZingboxCategory", "PanwIoTCategory"],
    "risk_score": ["ZingboxRiskScore", "PanwIoTRiskScore"],
    "risk score": ["ZingboxRiskScore", "PanwIoTRiskScore"],
    "confidence": ["ZingboxConfidence", "PanwIoTConfidence"],
    "confidence score": ["ZingboxConfidence", "PanwIoTConfidence"],
    "confidence_score": ["ZingboxConfidence", "PanwIoTConfidence"],
    "tag": ["ZingboxTag", "PanwIoTTag"],
    "asset_tag": ["ZingboxTag", "PanwIoTTag"],
    "Tags": ["ZingboxTag", "PanwIoTTag"],
    "hostname": ["ZingboxHostname", "PanwIoTHostname"],
    "osCombined": ["ZingboxOS", "PanwIoTOS"],
    "model": ["ZingboxModel", "PanwIoTModel"],
    "vendor": ["ZingboxVendor", "PanwIoTVendor"],
    "Serial Number": ["ZingboxSerial", "PanwIoTSerial"],
    "Serial_Number": ["ZingboxSerial", "PanwIoTSerial"],
    "endpoint protection": ["ZingboxEPP", "PanwIoTEPP"],
    "endpoint_protection": ["ZingboxEPP", "PanwIoTEPP"],
    "AET": ["ZingboxAET", "PanwIoTAET"],
    "External Network": ["ZingboxInternetAccess", "PanwIoTInternetAccess"],
    # "last activity": "ZingboxLastActivity"
}
'''
Get the error message or active cisco ise instance
'''


def get_active_ise_instance():
    # get active Cisco ISE instance
    response = demisto.executeCommand("GetCiscoISEActiveInstance", {})
    err_msg = None
    active_instance = None

    data = response[0].get('EntryContext', {})

    if 'PaloAltoIoTIntegrationBase.ActiveNodeInstance' in data:
        active_instance = data.get('PaloAltoIoTIntegrationBase.ActiveNodeInstance')
    elif 'PaloAltoIoTIntegrationBase.NodeErrorStatus' in data:
        err_msg = data.get('PaloAltoIoTIntegrationBase.NodeErrorStatus')

    return active_instance, err_msg


'''
Extract any connection error or error code if possible,
Otherwise just return the original error
'''
# Connection error = Connection Error. Verify that the Server URL and port are correct, and that the port is open.
# API call error =  Error in API call to Cisco ISE Integration [{response.status_code}] - {response.reason}, {message}


def extract_ise_api_error(err_msg):
    err_msg = err_msg.split('-')[0]
    if err_msg.startswith("Error in API call to Cisco"):
        start = err_msg.find('[') + 1
        end = err_msg.find(']')
        return err_msg[start:end]
    elif err_msg.startswith("Connection Error. Verify"):
        return "Connection Error"
    else:
        return err_msg


'''
returns a status and message back to cloud
'''


def send_status_to_panw_iot_cloud(status=None, msg=None):
    demisto.executeCommand("panw-iot-3rd-party-report-status-to-panw", {
        "status": status,
        "message": msg,
        "integrationName": "ise",
        "playbookName": "PANW IoT 3rd Party Cisco ISE Integration - Bulk Export to Cisco ISE",
        "type": "device",
        "timestamp": int(round(time.time() * 1000)),
        "using": "PANW IoT 3rd Party Integration Instance"
    })


GET_EP_ID_CMD = "cisco-ise-get-endpoint-id-by-name"
active_instance = demisto.args().get("active_ise_instance")
count = 0
offset = 0
PAGE_SIZE = 1000

while True:
    # get all devices from the IoT cloud
    resp = demisto.executeCommand("panw-iot-3rd-party-get-asset-list", {
        "assetType": "Device",
        "incrementTime": None,
        "offset": offset,
        "pageLength": PAGE_SIZE,
        "using": "PANW IoT 3rd Party Integration Instance"

    })
    if isError(resp[0]):
        err_msg = "Error, could not get devices from Iot Cloud %s" % resp[0].get('Contents')
        send_status_to_panw_iot_cloud("error", err_msg)
        demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % err_msg)
        return_error(err_msg)
        break
    size = 0
    try:
        device_list = resp[0]['Contents']
        size = len(device_list)
        for device_map in device_list:
            if 'mac_address' in device_map:
                mac = device_map['mac_address']
                if mac == None or mac == "":
                    continue
                attr_map = {}
                for field in device_map:
                    if device_map[field] == None or device_map[field] == "":
                        continue
                    if field in cisco_ise_field_map:
                        attr_map[cisco_ise_field_map[field][0]] = device_map[field]
                        attr_map[cisco_ise_field_map[field][1]] = device_map[field]
                # check if the endpoint already exists by the endpoint ID:
                resp = demisto.executeCommand(GET_EP_ID_CMD, {
                    "macAddress": mac,
                    "using": active_instance
                })
                if isError(resp[0]):
                    err_msg = extract_ise_api_error(resp[0]['Contents'])
                    # if this api call is not allowed (Method Not Allowed), we need to move to the older filter based API
                    if err_msg == '405':
                        GET_EP_ID_CMD = "cisco-ise-get-endpoint-id"
                        demisto.info("PANW_IOT_3RD_PARTY_BASE endpoint name API not available, switch to filter based get-endpoint-id API")
                    # If we get 404 Not Found or empty results are returned, we need to create a new Endpoint
                    elif err_msg == "404" or err_msg == "list index out of range":
                        ret = demisto.executeCommand("cisco-ise-create-endpoint", {
                            "mac_address": mac,
                            "attributes_map": attr_map,
                            "using": active_instance
                        })
                        if isError(ret[0]):
                            return_results("Failed to create new Endpoint %s" % mac)  # log to the war room
                            demisto.info("PANW_IOT_3RD_PARTY_BASE Failed to create new Endpoint %s, reason" %
                                         (mac, ret[0]['Contents']))
                        else:
                            #demisto.info("PANW_IOT_3RD_PARTY_BASE New Endpoint created %s" % mac)
                            count += 1
                    # The primary went down (connection Error) or 401 if a fail over occurred. We need to get the new Primary
                    elif err_msg == "Connection Error" or err_msg == "401":
                        # Failover can take up to 10 minutes, its ok to just wait even if its a standalone ISE noe.
                        msg = "ISE instance is down. Trying again in 10 minutes. Error = %s" % err_msg
                        demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % msg)
                        send_status_to_panw_iot_cloud("error", msg)
                        time.sleep(10 * 60)
                        # Try again to get a new active instance
                        new_active_instance, err_msg = get_active_ise_instance()
                        if new_active_instance == None:
                            send_status_to_panw_iot_cloud("error", err_msg)
                            demisto.info(
                                "PANW_IOT_3RD_PARTY_BASE failed to get any active ISE instance, sending report back to panw cloud. Error = %s", err_msg)
                            return_error(err_msg)
                        else:
                            active_instance = new_active_instance
                            msg = "Found active ISE instance %s" % active_instance
                            send_status_to_panw_iot_cloud("success", msg)
                            demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % msg)

                else:
                    try:
                        ID = resp[0]['EntryContext']['Endpoint(val.ID === obj.ID)']['ID']
                        attribute_names = ""
                        attribute_values = ""
                        for key in attr_map:
                            attribute_names += key + ","
                            attribute_values += str(attr_map[key]) + ","
                        attribute_names = attribute_names[:-1]
                        attribute_values = attribute_values[:-1]

                        res = demisto.executeCommand("cisco-ise-update-endpoint-custom-attribute", {
                            "id": ID,
                            "macAddress": mac,
                            "attributeName": attribute_names,
                            "attributeValue": attribute_values,
                            "using": active_instance
                        })
                        if isError(res[0]):
                            # this can happen if any of the custom attributes already exist on ISE
                            demisto.info("PANW_IOT_3RD_PARTY_BASE Failed to update Custom Attributes for Endpoint %s, reason" % (
                                mac, res[0]['Contents']))
                        else:
                            #demisto.info("PANW_IOT_3RD_PARTY_BASE Updated existing Endpoint %s" % mac)
                            count += 1
                    except:
                        continue
                time.sleep(1)
    except Exception as ex:
        demisto.info("PANW_IOT_3RD_PARTY_BASE Failed to parse device map %s" % str(ex))
        return_error("Failed to parse device map %s" % str(ex))

    if size == PAGE_SIZE:
        offset += PAGE_SIZE
        msg = "Successfully sent %d Devices to ISE" % count
        send_status_to_panw_iot_cloud("success", msg)
        demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % msg)
        time.sleep(5)
    else:
        break

msg = "Successfully sent total %d Devices to ISE" % count
send_status_to_panw_iot_cloud("success", msg)
demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % msg)
return_results(msg)
