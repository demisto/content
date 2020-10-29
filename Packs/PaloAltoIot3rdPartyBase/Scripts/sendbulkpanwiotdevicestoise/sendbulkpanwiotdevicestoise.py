import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
cisco_ise_field_map = {
    "ip": "ZingboxIpAddress",
    "ip address": "ZingboxIP",
    "ip_address": "ZingboxIP",
    "profile": "ZingboxProfile",
    "category": "ZingboxCategory",
    "risk_score": "ZingboxRiskScore",
    "risk score": "ZingboxRiskScore",
    "confidence": "ZingboxConfidence",
    "confidence score": "ZingboxConfidence",
    "confidence_score": "ZingboxConfidence",
    "tag": "ZingboxTag",
    "asset_tag": "ZingboxTag",
    "Tags": "ZingboxTag",
    "hostname": "ZingboxHostname",
    "osCombined": "ZingboxOS",
    "model": "ZingboxModel",
    "vendor": "ZingboxVendor",
    "Serial Number": "ZingboxSerial",
    "Serial_Number": "ZingboxSerial",
    "endpoint protection": "ZingboxEPP",
    "endpoint_protection": "ZingboxEPP",
    "AET": "ZingboxAET",
    # "External Network": "ZingboxInternetAccess",
    # "last activity": "ZingboxLastActivity"
}

res = []
count = 0
offset = 0
PAGE_SIZE = 1000
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
            "integration-name": "ISE",
            "playbook-name": "panw_iot_ise_bulk_integration",
            "type": "device",
            "timestamp": int(round(time.time() * 1000)),
            "using": "Palo Alto IoT Third-Party-Integration Base Instance"
        })
        return_error("Error, could not get devices from Iot Cloud")
    size = 0
    try:
        device_list = resp[0]['Contents']
        size = len(device_list)
        for device_map in device_list:
            if 'mac_address' in device_map:
                mac = device_map['mac_address']
                attr_map = {}
                for field in device_map:
                    if device_map[field] == None or device_map[field] == "":
                        continue
                    if field in cisco_ise_field_map:
                        attr_map[cisco_ise_field_map[field]] = device_map[field]
                # check if the endpoint already exists:
                # TODO: this command uses an older filter API, implement a new one using /ers/config/name/mac
                resp = demisto.executeCommand("cisco-ise-get-endpoint-id", {
                    "macAddress": mac,
                    "using": "PANW IoT ise Instance"
                })
                if isError(resp[0]):
                    # Hacky way, if we get a 404, that means we dont this Endpoint in ISE
                    # Create a new Endpoint here
                    return_results("Creating new Endpoint %s" % mac)
                    ret = demisto.executeCommand("cisco-ise-create-endpoint", {
                        "mac_address": mac,
                        "attributes_map": attr_map,
                        "using": "PANW IoT ise Instance"
                    })
                    if isError(ret[0]):
                        return_results("Failed to create new Endpoint %s" % mac)
                        # maybe send a report back to cloud here
                        return_results(ret)
                    else:
                        count += 1
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
                        return_results("Updating existing Endpoint %s" % mac)
                        res = demisto.executeCommand("cisco-ise-update-endpoint-custom-attribute", {
                            "id": ID,
                            "macAddress": mac,
                            "attributeName": attribute_names,
                            "attributeValue": attribute_values,
                            "using": "PANW IoT ise Instance"
                        })
                        if isError(resp[0]):
                            return_results("Failed to update Custom Attributes for Endpoint %s" % mac)
                            # maybe send a report back to cloud here
                        else:
                            count += 1
                    except:
                        continue
                time.sleep(1)
    except Exception as ex:
        demisto.results("Failed to parse device map %s" % str(ex))

    if size == PAGE_SIZE:
        offset += PAGE_SIZE
        demisto.executeCommand("send-status-to-panw-iot-cloud", {
            "status": "success",
            "message": "Successfully sent %d Devices to ISE" % count,
            "integration-name": "ISE",
            "playbook-name": "panw_iot_ise_bulk_integration",
            "type": "device",
            "timestamp": int(round(time.time() * 1000)),
            "using": "Palo Alto IoT Third-Party-Integration Base Instance"
        })
        demisto.results("Successfully sent %d Devices to ISE" % count)
        time.sleep(5)
    else:
        break

demisto.executeCommand("send-status-to-panw-iot-cloud", {
    "status": "success",
    "message": "Successfully sent total %d Devices to ISE" % count,
    "integration-name": "ISE",
    "playbook-name": "panw_iot_ise_bulk_integration",
    "type": "device",
    "timestamp": int(round(time.time() * 1000)),
    "using": "Palo Alto IoT Third-Party-Integration Base Instance"
})
demisto.results("Successfully sent total %d Devices to ISE" % count)
