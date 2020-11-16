import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
GET_EP_ID_CMD = "cisco-ise-get-endpoint-id-by-name"
ise_instance = demisto.args().get("active_ise_instance")
attr_lists = demisto.args().get("device_maps")
return_results("Processing %d devices" % len(attr_lists))
count = 0

'''
Extract any connection error or error code if possible,
Otherwise just return the original error
'''
# Connection error = Connection Error. Verify that the Server URL and port are correct, and that the port is open.
# API call error =  Error in API call to Cisco ISE Integration [{response.status_code}] - {response.reason}, {message}


def extract_ise_api_error(err_msg):
    #return_results("getting message = %s" % err_msg)
    err_msg = err_msg.split('-')[0]
    if err_msg.startswith("Error in API call to Cisco"):
        start = err_msg.find('[') + 1
        end = err_msg.find(']')
        return err_msg[start:end]
    elif err_msg.startswith("Connection Error. Verify"):
        return "Connection Error"
    else:
        return err_msg


for attr_list in attr_lists:
    mac = attr_list['mac']
    if mac == None or mac == "":
        continue
    attr_map = attr_list['zb_attributes']
    # check if the endpoint already exists by getting the endpoint ID.
    resp = demisto.executeCommand(GET_EP_ID_CMD, {
        "macAddress": mac,
        "using": ise_instance
    })
    if isError(resp[0]):
        # Hacky way to do this.. if we get a 404, that means the endpoint does not exist in ISE.
        # if we get a 405 we need to switch back to the filer based API
        err_msg = extract_ise_api_error(resp[0].get('Contents'))
        if err_msg == '405':
            GET_EP_ID_CMD = "cisco-ise-get-endpoint-id"
            demisto.info("PANW_IOT_3RD_PARTY_BASE name API not available, switch to filter based get-endpoint-id API")
        elif err_msg == "404" or err_msg == "list index out of range":
            # Create a new Endpoint here
            ret = demisto.executeCommand("cisco-ise-create-endpoint", {
                "mac_address": mac,
                "attributes_map": attr_map,
                "using": ise_instance
            })
            if isError(ret[0]):
                return_results("Failed to create new Endpoint %s" % mac)  # log to the war room
                demisto.info("PANW_IOT_3RD_PARTY_BASE Failed to create new Endpoint %s" % mac)
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
            res = demisto.executeCommand("cisco-ise-update-endpoint-custom-attribute", {
                "id": ID,
                "macAddress": mac,
                "attributeName": attribute_names,
                "attributeValue": attribute_values,
                "using": ise_instance
            })
            if isError(resp[0]):
                # The API will also return an error if any of custom attributes already exist.
                demisto.info("PANW_IOT_3RD_PARTY_BASE Failed to update Custom Attributes for Endpoint %s" % mac)
            else:
                count += 1
        except:
            continue

readable_status = "Successfully sent %d devices to ISE" % count
demisto.info("PANW_IOT_3RD_PARTY_BASE" + readable_status)
results = CommandResults(
    readable_output=readable_status,
    outputs_prefix="PaloAltoIoTIntegrationBase.Status",
    outputs=readable_status
)
return_results(results)
