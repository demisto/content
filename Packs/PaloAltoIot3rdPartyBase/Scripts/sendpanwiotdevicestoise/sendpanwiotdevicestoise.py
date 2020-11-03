import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


attr_lists = demisto.args().get("device_maps")
return_results("Processing %d devices" % len(attr_lists))
count = 0
for attr_list in attr_lists:
    mac = attr_list['mac']
    if mac == None or mac == "":
        continue
    attr_map = attr_list['zb_attributes']
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

readable_status = "Successfully sent %d devices to ISE" % count
results = CommandResults(
    readable_output=readable_status,
    outputs_prefix="PaloAltoIoTIntegrationBase.Status",
    outputs=readable_status
)
return_results(results)
