import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast
from datetime import datetime
from datetime import timedelta

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_HEADERS = {
    'X-Access-Key': demisto.params().get("Access Key"),
    'X-Key-Id': demisto.params().get("Key ID"),
    'Content-Type': 'application/json',
}
CUSTOMER_ID = demisto.params().get("Customer ID")
BASE_URL = demisto.params().get("url")
DEFAULT_PAGE_SIZE = 1000

api_type_map = {
    "Device": {
        "list_url": "pub/v4.0/device/list",
        "single_asset_url": "pub/v4.0/device",
        "context_path": "PanwIot3rdParty.Devices",
    },
    "Alert": {
        "list_url": "pub/v4.0/alert/list",
        "single_asset_url": "pub/v4.0/alert",
        "context_path": "PanwIot3rdParty.Alerts",
    },
    "Vulnerability": {
        "list_url": "pub/v4.0/vulnerability/list",
        "single_asset_url": "pub/v4.0/vulnerability",
        "context_path": "PanwIot3rdParty.Vulnerabilities",
    }
}

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
int_fields = ["risk_score", "risk score", "confidence", "confidence score", "confidence_score"]

device_fields_map = [
    ("ip_address", "dvc="),
    ("mac_address", "dvcmac="),
    ("hostname", "dvchost="),
    ("profile", "cs1Label=Profile cs1="),
    ("category", "cs2Label=Category cs2="),
    ("profile_type", "cs1Labe3=Profile cs3="),
    ("vendor", "cs4Label=Vendor cs4="),
    ("model", "cs5Label=Model cs5="),
    ("vlan", "cs6Label=Vlan cs6="),
    ("site_name", "cs7Label=Site cs7="),
    ("risk_score", "cs8Label=RiskScore cs8="),
    ("risk_level", "cs9Label=RiskLevel cs9="),
    ("subnet", "cs10Label=Subnet cs10="),
    ("number_of_critical_alerts", "cs11Label=NumCriticalAlerts cs11="),
    ("number_of_warning_alerts", "cs12Label=NumWarningAlerts cs12="),
    ("number_of_caution_alerts", "cs13Label=NumCautionAlerts cs13="),
    ("number_of_info_alerts", "cs14Label=NumInfoAlerts cs14="),
    ("first_seen_date", "cs15Label=FirstSeenDate cs15="),
    ("confidence_score", "cs16Label=ConfidenceScore cs16="),
    ("os_group", "cs17Label=OsGroup cs17="),
    ("os/firmware_version", "cs18Label=OsFirmwareVersion cs18="),
    ("OS_Support", "cs19Label=OsSupport cs19="),
    ("OS_End_of_Support", "cs20Label=OsEndOfSupport cs20="),
    ("Serial_Number", "cs21Label=SerialNumber cs21="),
    ("endpoint_protection", "cs22Label=EndpointProtection cs22="),
    ("NetworkLocation", "cs23Label=NetworkLocation cs23="),
    ("AET", "cs24Label=AET cs24="),
    ("DHCP", "cs25Label=DHCP cs25="),
    ("wire_or_wireless", "cs26Label=WireOrWireless cs26="),
    ("SMB", "cs27Label=SMB cs27="),
    ("Switch_Port", "cs28Label=SwitchPort cs28="),
    ("Switch_Name", "cs29Label=SwitchName cs29="),
    ("Switch_IP", "cs30Label=SwitchIp cs30="),
    ("services", "cs31Label=Services cs31="),
    ("is_server", "cs32Label=IsServer cs32="),
    ("NAC_profile", "cs33Label=NAC_Profile cs33="),
    ("NAC_profile_source", "cs34Label=NAC_ProfileSource cs34="),
    ("Access_Point_IP", "cs35Label=AccessPointIp cs35="),
    ("Access_Point_Name", "cs36Label=AccessPointName cs36="),
    ("SSID", "cs37Label=SSID cs37="),
    ("Authentication_Method", "cs38Label=AuthMethod cs38="),
    ("Encryption_Cipher", "cs39Label=EncryptionCipher cs39="),
    ("AD_Username", "cs40Label=AD_Username cs40="),
    ("AD_Domain", "cs41Label=AD_Domain cs41="),
    ("Applications", "cs42Label=Applications cs42="),
    ("Tags", "cs43Label=Tags cs43="),
    ("os_combined", "cs44Label=os_combined cs44=")]

vulnerabilities_fields_map = [
    ("ip", "dvc="),
    ("deviceid", "dvcmac="),
    ("name", "dvchost="),
    ("profile", "cs1Label=Profile cs1="),
    ("display_profile_category", "cs2Label=Category cs2="),
    ("profile_vertical", "cs1Labe3=Profile cs3="),
    ("vendor", "cs4Label=Vendor cs4="),
    ("model", "cs5Label=Model cs5="),
    ("vlan", "cs6Label=Vlan cs6="),
    ("site_name", "cs7Label=Site cs7="),
    ("risk_score", "cs8Label=RiskScore cs8="),
    ("risk_level", "cs9Label=RiskLevel cs9="),
    ("subnet", "cs10Label=Subnet cs10="),
    ("vulnerability_name", "cs11Label=vulnerabilityName cs11="),
    ("detected_date", "cs12Label=DetectionDate cs12="),
    ("remediate_instruction", "cs13Label=RemediateInstructions cs13="),
    ("remediate_checkbox", "cs14Label=RemediateCheckbox cs14="),
    ("first_seen_date", "cs15Label=FirstSeenDate cs15="),
    ("confidence_score", "cs16Label=ConfidenceScore cs16="),
    ("os", "cs17Label=OsGroup cs17="),
    ("os/firmware_version", "cs18Label=OsFirmwareVersion cs18="),
    ("osCombined", "cs19Label=OsSupport cs19="),
    ("OS_End_of_Support", "cs20Label=OsEndOfSupport cs20="),
    ("Serial_Number", "cs21Label=SerialNumber cs21="),
    ("endpoint_protection", "cs22Label=EndpointProtection cs22="),
    ("NetworkLocation", "cs23Label=NetworkLocation cs23="),
    ("AET", "cs24Label=AET cs24="),
    ("DHCP", "cs25Label=DHCP cs25="),
    ("wire_or_wireless", "cs26Label=WireOrWireless cs26="),
    ("SMB", "cs27Label=SMB cs27="),
    ("Switch_Port", "cs28Label=SwitchPort cs28="),
    ("Switch_Name", "cs29Label=SwitchName cs29="),
    ("Switch_IP", "cs30Label=SwitchIp cs30="),
    ("services", "cs31Label=Services cs31="),
    ("is_server", "cs32Label=IsServer cs32="),
    ("NAC_profile", "cs33Label=NAC_Profile cs33="),
    ("NAC_profile_source", "cs34Label=NAC_ProfileSource cs34="),
    ("Access_Point_IP", "cs35Label=AccessPointIp cs35="),
    ("Access_Point_Name", "cs36Label=AccessPointName cs36="),
    ("SSID", "cs37Label=SSID cs37="),
    ("Authentication_Method", "cs38Label=AuthMethod cs38="),
    ("Encryption_Cipher", "cs39Label=EncryptionCipher cs39="),
    ("AD_Username", "cs40Label=AD_Username cs40="),
    ("AD_Domain", "cs41Label=AD_Domain cs41="),
    ("Applications", "cs42Label=Applications cs42="),
    ("Tags", "cs43Label=Tags cs43=")]


def http_request(method, url, api_params={}, data=None):

    params = (
        ('customerid', CUSTOMER_ID),
    )
    if api_params:
        params += api_params
    try:
        LOG(f'running {method} request with url={url}')
        response = requests.request(method, url, headers=DEFAULT_HEADERS, params=params, data=data)
    except requests.exceptions.ConnectionError as e:
        err_msg = "Failed to connect to PANW IoT Cloud. Verify assess_key, key_id and url are correct."
        return_error(err_msg)

    if response.status_code not in {200, 201, 202, 204}:
        err_msg = f'Error in API call to PANW IoT Cloud  [{response.status_code}] - {response.reason}'
        return_error(err_msg)

    if response.status_code in (201, 204):  # 201-Created OR 204-No Content
        return
    try:
        response = response.json()
    except ValueError:
        err_msg = "Failed to parse ouput for API call %s" % url
        return_error(err_msg)

    return response


def get_asset_list():
    """
    Returns a list of assets for the specifed asset type.
    """
    asset_type = demisto.args().get('assetType')
    increment_time = demisto.args().get('incrementTime')
    page_length = demisto.args().get('pageLength')
    offset = demisto.args().get('offset')

    url = BASE_URL + api_type_map[asset_type]['list_url']
    one_call = False

    # if either page_length or offset is set, we dont need to accumulate results
    if page_length or offset:
        one_call = True

    asset_list = []
    poll_time = None  # Device API uses poll time
    stime = None  # Alerts and Vulns use stime

    if page_length == None:
        page_length = DEFAULT_PAGE_SIZE
    if offset == None:
        offset = '0'
    if increment_time:
        if asset_type == "Device":
            poll_time = int(round(time.time() * 1000)) - int(increment_time) * 60 * 1000
        else:
            stime = datetime.now() - timedelta(minutes=int(increment_time))

    params = (
        ('offset', str(offset)),
        ('pagelength', str(page_length)),
        ('stime', stime),
    )
    if asset_type == "Device":
        params += (('detail', 'true'),)
        params += (('last_poll_time', poll_time),)
    elif asset_type == "Vulnerability":
        params += (('groupby', 'device'),)

    # gather all the results, break if the return size is less than requested page size
    while True:
        response = http_request('GET', url, params)
        size = 0
        if asset_type == "Device":
            asset_list.extend(response.get('devices'))
            size = response.get('total')
        else:
            asset_list.extend(response.get('items'))
            size = len(response.get('items'))
        if one_call or size < page_length:
            break
        else:
            offset += page_length
    op_data = {
        "asset type": asset_type,
        "assets pulled": len(asset_list)
    }
    return CommandResults(
        readable_output=tableToMarkdown("Asset import summary:", op_data, removeNull=True),
        outputs_prefix=api_type_map[asset_type]['context_path'],
        outputs=asset_list
    )


def get_single_asset():
    """
    For input asset type and asset ID,
    returns the asset details.
    """

    asset_type = demisto.args().get('assetType')
    asset_id = demisto.args().get('assetID')

    if asset_type == None:
        return_error("Invalid Asset Type ")
    if asset_id == None:
        return_error("Invalid Asset ID")

    params = ()
    if asset_type == 'Device':
        params += (
            ('detail', 'true'),
            ('deviceid', str(asset_id)),
        )
    elif asset_type == 'Alert':
        params += (
            ('zb_ticketid', str(asset_id)),
        )
    elif asset_type == 'Vulnerability':
        params += (
            ('groupby', 'device'),
            ('zb_ticketid', str(asset_id)),
        )
    else:
        return_error("Invalid asset type")

    url = BASE_URL + api_type_map[asset_type]['single_asset_url']

    data = http_request('GET', url, params)

    if asset_type == 'Alert' or asset_type == 'Vulnerability':
        data = data.get('items')
    msg = "Successfully pulled %s (%s) from PANW IoT Cloud" % (asset_type, asset_id)

    return CommandResults(
        readable_output="Successfully pulled %s (%s) from PANW IoT Cloud" % (asset_type, asset_id),
        outputs_prefix="PanwIot3rdParty.SingleAsset",
        outputs=data
    )


def report_status_to_iot_cloud():
    """
    Reports status details back to PANW IoT Cloud.
    """
    status = demisto.args().get('status')
    message = demisto.args().get('message')
    integration_name = demisto.args().get('integrationName')
    playbook_name = demisto.args().get('playbookName')
    asset_type = demisto.args().get('type')

    curr_time = int(round(time.time() * 1000))

    data = {
        "playbook_name": playbook_name,
        "integration_name": integration_name,
        "message": message,
        "status": status,
        "type": asset_type,
        "timestamp": curr_time
    }
    api_data = json.dumps(data)

    url = BASE_URL + "pub/v4.0/xsoar/status"
    response = http_request('POST', url, None, api_data)
    data["iot_cloud_response"] = response

    return CommandResults(
        readable_output=tableToMarkdown("Reporting Status:", data, removeNull=True)
    )


def convert_vulnerability_list_to_cef(vulnerability_list=None):
    """
    Converts a PANW IoT vulnerability list to CEF formatted syslogs.
    """
    data = []
    risk_level_map = {'Critical': '10', 'High': '6', 'Medium': '3', 'Low': '1'}

    for vulnerability in vulnerability_list:
        line = "INFO:siem-syslog:CEF:0|PaloAltoNetworks|PANWIOT|1.0|vulnerability|"
        if "vulnerability_name" in vulnerability:
            line += vulnerability['vulnerability_name'] + "|"
        if "risk_level" in vulnerability:
            if vulnerability["risk_level"] in risk_level_map:
                line += risk_level_map[vulnerability["risk_level"]] + "|"
            else:
                line += "1|"  # default severity

        for t in vulnerabilities_fields_map:
            input_field = t[0]
            output_field = t[1]
            # print input_field, output_field
            if input_field in vulnerability:
                val = vulnerability[input_field]
            else:
                val = ""
            if output_field and val:
                line += str(output_field) + str(val) + " "
        data.append(line)

    return data


def convert_alert_list_to_cef(alert_list=None):
    """
    Converts a PANW IoT alert list to CEF formatted syslogs.
    """
    data = []
    for alert in alert_list:
        if alert != None and "msg" in alert and "status" in alert["msg"] and alert["msg"]["status"] == "publish":
            msg = alert['msg']
            line = "CEF:0|PaloAltoNetworks|PANWIOT|1.0|PaloAltoNetworks Alert:policy_alert|"

            if "name" in alert:
                line += alert["name"] + "|"
            if "severityNumber" in alert:
                line += str(alert["severityNumber"]) + "|"
            if "deviceid" in alert:
                line += "dvcmac=%s " % alert["deviceid"]
            if "fromip" in msg:
                line += "src=%s " % msg["fromip"]
            if "toip" in msg:
                line += "dst=%s " % msg["toip"]
            if "hostname" in msg:
                line += "shost=%s " % msg["hostname"]
            if "toURL" in msg:
                line += "dhost=%s " % msg["toURL"]
            if "id" in msg:
                line += "fileId=%s " % msg["id"]
                line += "fileType=alert "

            if "date" in alert:
                line += "rt=%s " % str(msg["id"])
            if "generationTimestamp" in msg:
                line += "deviceCustomDate1=%s " % str(msg["generationTimestamp"])

            description = None
            values = []
            if "description" in alert:
                description = alert["description"]
            if "values" in msg:
                values = msg["values"]

            line += "cs1Label=Description cs1=%s " % description
            line += "cs2Label=Values cs2=%s " % str(values)
            data.append(line)

    return data


def convert_device_list_to_cef(device_list=None):
    """
    Converts a PANW IoT device attribute list to CEF formatted syslogs.
    """
    data = []
    for device_map in device_list:
        if 'mac_address' in device_map:
            line = "INFO:siem-syslog:CEF:0|PaloAltoNetworks|PANWIOT|1.0|asset|Asset Identification|1|"
            for t in device_fields_map:
                input_field = t[0]
                output_field = t[1]
                # print input_field, output_field
                if input_field in device_map:
                    val = device_map[input_field]
                else:
                    val = ""
                if output_field and val:
                    line += str(output_field) + str(val) + " "
            data.append(line)
    return data


def convert_device_list_to_ise_attributes(device_list=None):
    """
    Converts a PANW IoT device attribute list to Cisco ISE custom attributes.
    """
    data = []
    for device_map in device_list:
        if 'mac_address' in device_map:
            if device_map['mac_address'] == None or device_map['mac_address'] == "":
                continue
            attribute_list = {}
            attribute_list['mac'] = device_map['mac_address']
            zb_attributes = {}
            for field in device_map:
                if device_map[field] == None or device_map[field] == "":
                    continue
                if field in cisco_ise_field_map:
                    if field in int_fields:
                        try:
                            int_val = int(device_map[field])
                        except:
                            continue
                        zb_attributes[cisco_ise_field_map[field][0]] = int_val
                        zb_attributes[cisco_ise_field_map[field][1]] = int_val
                    else:
                        zb_attributes[cisco_ise_field_map[field][0]] = device_map[field]
                        zb_attributes[cisco_ise_field_map[field][1]] = device_map[field]
            attribute_list['zb_attributes'] = zb_attributes
            data.append(attribute_list)

    return data


def convert_asset_to_external_format():
    """
    For a given asset (alert, device, vuln) converts it
    to specified 3rd party format.
    """

    prefixMap = {
        "Device": {
            "SIEM": "PanwIot3rdParty.DeviceCEFSyslogs",
            "CiscoISECustomAttributes": "PanwIot3rdParty.CiscoISEAttributes"
        },
        "Alert": {
            "SIEM": "PanwIot3rdParty.AlertCEFSyslogs",
        },
        "Vulnerability": {
            "SIEM": "PanwIot3rdParty.VulnerabilityCEFSyslogs",
        },
    }

    asset_type = demisto.args().get('assetType')
    output_format = demisto.args().get('outputFormat')
    asset_list = demisto.args().get('assetList')

    data = []
    if asset_list:
        if asset_type == "Device":
            if output_format == "CiscoISECustomAttributes":
                data = convert_device_list_to_ise_attributes(asset_list)
            elif output_format == "SIEM":
                data = convert_device_list_to_cef(asset_list)
            elif output_format == "ServiceNow":
                # Shuai to do this
                LOG("adding a line here")
            else:
                return_error("Output format %s not supported for Devices" % output_format)
        elif asset_type == "Alert":
            if output_format == "SIEM":
                data = convert_alert_list_to_cef(asset_list)
            elif output_format == "ServiceNow":
                # Shuai to do this
                LOG("adding a line here")
            else:
                return_error("Output format %s not supported for Alerts" % output_format)
        elif asset_type == "Vulnerability":
            if output_format == "SIEM":
                data = convert_vulnerability_list_to_cef(asset_list)
            elif output_format == "ServiceNow":
                # Shuai to do this
                LOG("adding a line here")
            else:
                return_error("Output format %s not supported for Vulnerabilities" % output_format)
        else:
            return_error("Invalid asset type %s" % asset_type)

    prefix = prefixMap[asset_type][output_format]
    return CommandResults(
        readable_output="Converted %d %s to %s" % (len(data), asset_type, output_format),
        outputs_prefix=prefix,
        outputs=data
    )


def connection_test_command(return_bool: bool = False):
    """
    Try to get a single device from the Cloud to test connectivity.
    """
    params = (
        ('offset', '0'),
        ('pagelength', '1'),
        ('detail', 'false'),
    )
    url = BASE_URL + api_type_map['Device']['list_url']
    data = http_request('GET', url, params)

    if return_bool:
        return True


def main() -> None:
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            if connection_test_command(True):
                demisto.results('ok')
            else:
                demisto.results('test failed')
        elif demisto.command() == 'panw-iot-3rd-party-get-asset-list':
            results = get_asset_list()
            return_results(results)
        elif demisto.command() == 'panw-iot-3rd-party-get-single-asset':
            results = get_single_asset()
            return_results(results)
        elif demisto.command() == 'panw-iot-3rd-party-report-status-to-panw':
            results = report_status_to_iot_cloud()
            return_results(results)
        elif demisto.command() == 'panw-iot-3rd-party-convert-assets-to-external-format':
            results = convert_asset_to_external_format()
            return_results(results)
        # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
