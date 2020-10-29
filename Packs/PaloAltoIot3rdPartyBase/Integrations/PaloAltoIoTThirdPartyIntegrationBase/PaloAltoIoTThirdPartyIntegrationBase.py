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

KEY_ID = demisto.params().get("Key ID")
ACCESS_KEY = demisto.params().get("Access Key")
CUSTOMER_ID = demisto.params().get("Customer ID")
BASE_URL = demisto.params().get("url")
DEFAULT_PAGE_SIZE = 1000

api_type_map = {
    "Devices": {
        "url": "pub/v4.0/device/list",
        "single_asset_url": "pub/v4.0/device",
        "output_path": "PaloAltoIoTIntegrationBase.Devices",
        "status_path": "PaloAltoIoTIntegrationBase.DeviceInventoryStatus"
    },
    "Alerts": {
        "url": "pub/v4.0/alert/list",
        "single_asset_url": "pub/v4.0/alert",
        "output_path": "PaloAltoIoTIntegrationBase.Alerts",
        "status_path": "PaloAltoIoTIntegrationBase.AlertStatus"
    },
    "Vulnerabilities": {
        "url": "pub/v4.0/vulnerability/list",
        "single_asset_url": "pub/v4.0/vulnerability",
        "output_path": "PaloAltoIoTIntegrationBase.Vulnerabilities",
        "status_path": "PaloAltoIoTIntegrationBase.VulnerabilityStatus"
    }
}

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
    "vendor":"ZingboxVendor",
    "Serial Number": "ZingboxSerial",
    "Serial_Number": "ZingboxSerial",
    "endpoint protection": "ZingboxEPP",
    "endpoint_protection": "ZingboxEPP",
    "AET":"ZingboxAET",
    #"External Network": "ZingboxInternetAccess",
    #"last activity": "ZingboxLastActivity"
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
    ("Tags", "cs43Label=Tags cs43=")]

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


def convert_device_map_to_cef():
    device_details = demisto.args().get('deviceList')
    opList = []
    if 'mac_address' in device_details:
        line = "INFO:siem-syslog:CEF:0|PaloAltoNetworks|PANWIOT|1.0|asset|Asset Identification|1|"
        for t in device_fields_map:
            input_field = t[0]
            output_field = t[1]
            # print input_field, output_field
            if input_field in device_details:
                val = device_details[input_field]
            else:
                val = ""
            if output_field and val:
                line += str(output_field) + str(val) + " "
        opList.append(line)

    return CommandResults(
        readable_output="Device inventory CEF Syslog",
        outputs_prefix='PaloAltoIoTIntegrationBase.DeviceSyslogs',
        outputs=opList
    )


def convert_alert_map_to_cef():
    alert = demisto.args().get('alertList')
    opList = []
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
        opList.append(line)
        return CommandResults(
            readable_output="Alert CEF Syslog",
            outputs_prefix='PaloAltoIoTIntegrationBase.AlertSyslogs',
            outputs=line
        )


def convert_vulnerability_map_to_cef():
    vulnerability = demisto.args().get('VulnerabilityList')
    opList = []

    risk_level_map = {'Critical': '10', 'High': '6', 'Medium': '3', 'Low': '1'}

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
    opList.append(line)

    return CommandResults(
        readable_output="Vulnerability CEF Syslog",
        outputs_prefix='PaloAltoIoTIntegrationBase.VulnerabilitySyslogs',
        outputs=opList
    )


def run_get_request(api_type, api_url, stime=None, offset=0):
    if stime == None:
        stime = '-1'
    url = BASE_URL + api_url
    millis = int(round(time.time() * 1000)) - 15*60*1000
    params = (
        ('customerid', CUSTOMER_ID),
        ('key_id', KEY_ID),
        ('access_key', ACCESS_KEY),
        ('stime', stime),
        ('offset', str(offset)),
        ('pagelength', str(DEFAULT_PAGE_SIZE)),
    )
    if api_type == "Devices":
        params += (
            ('detail', 'true'),
        )
        # bulk update here
        if stime != '-1':
            params += (
                ('last_poll_time', millis),
            )
    elif api_type == "Vulnerabilities":
        params += (('groupby', 'device'),)

    response = None
    try:
        response = requests.get(url, params=params)
        code = response.status_code
        if code < 300:
            status = "Success"
        else:
            status = "HTTP error code = %s, url = %s" % (str(code), url)
    except requests.exceptions.RequestException as e:
        status = "Failed connection to %s\n%s" % (url, e)
    return status, response


def write_status_context_data(status_path, message, status, count):
    existing_data = demisto.getIntegrationContext()
    existing_data[status_path] = {
        "message": message,
        "status": status,
        "count": count,
        "timestamp": str(datetime.now())
    }
    demisto.setIntegrationContext(existing_data)


def get_servicenow_device_query(args):

    device_list = args.get("devices")
    deviceids = [device['deviceid'] for device in device_list]

    query = "mac_addressIN" + ",".join(deviceids)

    return CommandResults(
        readable_output="Service Table Device Query is %s" % (query),
        outputs_prefix='PaloAltoIoTIntegrationBase.Query',
        outputs=query
    )


"""
the return example:
{
    insert: [
        {
            fields: "key1=value1;key2=value2;key3=value3;...",
            custom_fields: "key1=value4;key2=value5;key3=value6;..."
        },
        {
            fields: "key1=value1;key2=value2;key3=value3;...",
            custom_fields: "key1=value4;key2=value5;key3=value6;..."
        },
        ...
    ],

    update: [
        {
            sys_id: 'sys_id_1',
            fields: "key1=value1;key2=value2;key3=value3;...",
            custom_fields: "key1=value4;key2=value5;key3=value6;..."

        },
        {
            sys_id: 'sys_id_2'
            fields: "key1=value1;key2=value2;key3=value3;...",
            custom_fields: "key1=value4;key2=value5;key3=value6;..."
        }
        ...
    ]

}
"""


def get_servicenow_upsert_devices(args):

    sn_id_deviceids = args.get("sn_id_deviceids")
    device_list = args.get("devices")
    ids_map = {}
    if sn_id_deviceids:
        for i in range(len(sn_id_deviceids)):
            ids = sn_id_deviceids[i]
            sn_id = ids["ID"]
            deviceid = ids["mac_address"]
            ids_map[deviceid] = sn_id

    update_list = []
    insert_list = []
    for i in range(len(device_list)):
        device = device_list[i]
        deviceid = device["deviceid"]
        instance = convert_device_to_servicenow_format(device)
        if (not ids_map) | (deviceid not in ids_map):
            insert_list.append(instance)
        else:
            sn_id = ids_map[deviceid]
            instance["sys_id"] = sn_id
            update_list.append(instance)

    result = {}
    result["insert"] = insert_list
    result["update"] = update_list

    return CommandResults(
        readable_output="Service Table Device Upserting List",
        outputs_prefix='PaloAltoIoTIntegrationBase.UpsertDevices',
        outputs=result
    )


"""
return example:
[
    {
        fields: "key1=value1;key2=value2;key3=value3;...",
        custom_fields: value4;key2=value5;key3=value6;...
    },
    {
        fields: "key1=value1;key2=value2;key3=value3;...",
        custom_fields: value4;key2=value5;key3=value6;...
    },
    ...
]
"""


def get_servicenow_devices_query_batch(args):
    data = args.get('devices')
    query_strs = []
    query_str = 'mac_addressIN'
    DEFAULT_VALUE_SIZE = 2

    for i in range(len(data)):
        query_str += entry['deviceid'] + ','
        if ((i + 1) % DEFAULT_VALUE_SIZE == 0 or i == (len(data) - 1)):
            query_strs.append(query_str)
            query_str = 'mac_addressIN'

    return CommandResults(
        readable_output="Total data length is " + str(len(data)) + ". Query List: " + ("\n".join(query_str)),
        outputs_prefix='PaloAltoIoTIntegrationBase.BatchQuery',
        outputs=query_strs
    )


def convert_device_to_servicenow_format(device):
    device_fields_mapping = {
        "hostname": "name",
        "ip_address": "ip_address",
        "deviceid": "mac_address"
    }
    device_custome_fields_mapping = {
        "category": "u_category",
        "profile": "u_profile",
        "display_tags": "u_iot_tag",
        "vendor": "u_iot_vendor",
        "model": "u_iot_model",
        "os_group": "u_iot_os",
        "SSID": "u_iot_ssid",
        "site_name": "u_iot_site",
        "vlan": "u_iot_vlan",
        "wire_or_wireless": "u_iot_wired_wireless",
        "os_support": "u_os_support"
    }
    instance = {}
    fields = ''
    custom_fields = ''

    for field in device_fields_mapping:
        sn_name = device_fields_mapping[field]
        value = ''
        if field in device:
            if device[field] != None:
                value = str(device[field])
        else:
            value = ' '
        fields += (sn_name + "=" + value + ";")
    instance["fields"] = fields

    for field in device_custome_fields_mapping:
        sn_name = device_custome_fields_mapping[field]
        value = ''
        if field in device:
            if device[field] != None:
                value = str(device[field])
        else:
            value = ' '
        custom_fields += (sn_name + "=" + value + ";")

    instance["custom_fields"] = custom_fields
    return instance


def convert_alert_to_servicenow(args):
    incident = args.get('incident')
    comments_and_work_notes = str(incident['comments_and_work_notes'])
    url = str(incident['url'])
    urgency = str(incident['urgency'])
    incident.setdefault('user_email', 'cannot find any email')
    user_email = incident['user_email']
    zb_ticketid = incident['correlation_id']

    alert = args.get('alert')
    alert.setdefault('msg', {}).setdefault('impact', 'Sorry, no impact available to display so far!')
    alert.setdefault('msg', {}).setdefault('recommendation', {}).setdefault(
        'content', ['Sorry, no recommendation available to display so far!'])
    alert.setdefault('location', 'Sorry, location is not provided')
    alert.setdefault('category', 'Sorry, category is not provided')
    alert.setdefault('profile', 'Sorry, profile is not provided')
    alert.setdefault('description', 'Sorry, description is not provided')

    impact = alert['msg']['impact']
    recommendations = alert['msg']['recommendation']['content']
    recommendation_text = ''
    alert_description = str(alert['description'])
    category = alert['category']
    profile = alert['profile']
    location = alert['location']
    short_description = alert['name']

    for rec in recommendations:
        recommendation_text += '*' + rec + '\n'

    description = 'Summary\n' + alert_description + '\n\nCategory: ' + category + " Profile: " + profile\
        + '\n\nImpact\n' + impact + '\n\nRecommendations\n' + recommendation_text + '\nURL\n' + url

    result = 'urgency=' + urgency + ';location=' + location + ';short_description=' + short_description\
        + ';comments_and_work_notes=' + comments_and_work_notes + ';description=' + description\
        + ';correlation_id=' + zb_ticketid + ';impact=3;company=Palo Alto Networks;opened_by=svc_panw_iot;'

    return CommandResults(
        readable_output=result,
        outputs_prefix='PaloAltoIoTIntegrationBase.AlertSN',
        outputs=result
    )


def convert_vulnerability_to_servicenow(args):
    incident = args.get('incident')
    comments_and_work_notes = str(incident['comments_and_work_notes'])
    url = str(incident['url'])
    urgency = str(incident['urgency'])
    incident.setdefault('user_email', 'cannot find any email')
    user_email = incident['user_email']
    zb_ticketid = incident['correlation_id']

    vuln = args.get('vulnerability')
    vuln.setdefault('msg', {}).setdefault('impact', 'Sorry, no impact available to display so far!')
    vuln.setdefault('msg', {}).setdefault('recommendation', {}).setdefault(
        'content', ['Sorry, no recommendation available to display so far!'])
    vuln.setdefault('category', 'Sorry, category is not provided')
    vuln.setdefault('profile', 'Sorry, profile is not provided')
    vuln.setdefault('description', 'Sorry, description is not provided')
    vuln.setdefault('location', 'Sorry, location is not provided')
    impact = vuln['msg']['impact']
    recommendations = vuln['msg']['recommendation']['content']
    recommendation_text = ''
    alert_description = str(vuln['description'])
    category = str(vuln['category'])
    profile = str(vuln['profile'])
    location = str(vuln['location'])
    short_description = str(vuln['name'])

    for rec in recommendations:
        recommendation_text += '*' + rec + '\n'

    description = 'Summary\n' + alert_description + '\n\nCategory: ' + category + " Profile: " + profile\
        + '\n\nImpact\n' + impact + '\n\nRecommendations\n' + recommendation_text + '\nURL\n' + url

    result = 'urgency=' + urgency + ';location=' + location + ';short_description=' + short_description\
        + ';comments_and_work_notes=' + comments_and_work_notes + ';description=' + description\
        + ';correlation_id=' + zb_ticketid + ';impact=3;company=Palo Alto Networks;opened_by=svc_panw_iot;'

    return CommandResults(
        readable_output=result,
        outputs_prefix='PaloAltoIoTIntegrationBase.VulnerabilitySN',
        outputs=result
    )


def run_api_command(api_type, delay=-1):

    if api_type not in api_type_map:
        return_error("Invalid API type")

    api_url = api_type_map[api_type]['url']
    output_path = api_type_map[api_type]['output_path']
    status_path = api_type_map[api_type]['status_path']

    asset_list = []
    offset = 0
    count = 0
    if delay != -1:
        stime = datetime.now() - timedelta(minutes=delay)
    else:
        stime = None
    # Loop to gather all data available, each req
    while True:
        status, response = run_get_request(api_type, api_url, stime, offset)
        # if API failed, write error status to context so we can forward this back to the cloud
        if status != "Success":
            write_status_context_data(status_path, status, "Error", -1)
            return_error(status)
        try:
            data = json.loads(response.text)
            if api_type == "Devices":
                assets = data['devices']
                count = data['total']
            else:
                assets = data['items']
                count = len(data['items'])
            asset_list.extend(assets)
            if count == DEFAULT_PAGE_SIZE:
                offset += DEFAULT_PAGE_SIZE
            else:
                break
        except Exception as e:
            status = "Exception in parsing %s API response %s" % (api_type, str(e))
            write_status_context_data(status_path, status, "Error", -1)
            return_error(status)

    return_message = "Total %s pulled from IoT cloud %d" % (api_type, len(asset_list))
    write_status_context_data(status_path, return_message, status, len(asset_list))

    data = {
        "asset_list": asset_list,
        "count": len(asset_list),
        "status": return_message
    }

    return CommandResults(
        readable_output=return_message,
        outputs_prefix=output_path,
        outputs=data
    )


def send_status_to_iot_cloud():
    status = demisto.args().get('status')
    message = demisto.args().get('message')
    integration_name = demisto.args().get('integration-name')
    playbook_name = demisto.args().get('playbook-name')
    asset_type = demisto.args().get('type')

    curr_time = int(round(time.time() * 1000))

    if message is None:
        count = 55
        message = "Successfully sent %d to %s" % (count, integration_name)

    data = {
        "playbook_name": playbook_name,
        "integration_name": integration_name,
        "message": message,
        "status": status,
        "type": asset_type,
        "timestamp": curr_time
    }
    out_data = json.dumps(data)

    headers = {
        'X-Access-Key': ACCESS_KEY,
        'X-Key-Id': KEY_ID,
        'Content-Type': 'application/json',
    }
    params = (
        ('customerid', CUSTOMER_ID),
    )
    url = BASE_URL + "pub/v4.0/xsoar/status"
    response = requests.post(url, headers=headers,
                             params=params, data=out_data, verify=False)
    data["iot_cloud_response"] = response.text
    return CommandResults(
        readable_output=data
    )


'''
def get_single_device_details(args):
    device_id = demisto.args().get('mac')
    params = (
        ('customerid', CUSTOMER_ID),
        ('key_id', KEY_ID),
        ('access_key', ACCESS_KEY),
        ('deviceid', device_id),
    )
    url = BASE_URL + "pub/v4.0/device"
    response = requests.get(url,params=params, verify=False)
    data = json.loads(response.text)
    if response.status_code != 200:
        data = []
    # handle errors here later,
    return CommandResults(
        readable_output=data,
        outputs_prefix="PaloAltoIoTIntegrationBase.SingleDevices",
        outputs=data
    )

def get_single_vulnerability_details(args):
    vulnerability_id = demisto.args().get('vulnerability_id')
    params = (
        ('customerid', CUSTOMER_ID),
        ('key_id', KEY_ID),
        ('access_key', ACCESS_KEY),
        ('zb_ticketid', vulnerability_id),
        ('groupby', 'device'),
    )
    url = BASE_URL + "pub/v4.0/vulnerability"
    response = requests.get(url,params=params, verify=False)
    data = json.loads(response.text)
    if 'items' in data and len(data['items']):
        data = data['items']
    else:
        data = []
    # handle errors here later,
    return CommandResults(
        readable_output=data,
        outputs_prefix="PaloAltoIoTIntegrationBase.SingleVulnerability",
        outputs=data
    )

def get_single_alert_details(args):
    alert_id = demisto.args().get('alert_id')
    params = (
        ('customerid', CUSTOMER_ID),
        ('key_id', KEY_ID),
        ('access_key', ACCESS_KEY),
        ('zb_ticketid', alert_id),
    )
    url = BASE_URL + "pub/v4.0/alert"
    response = requests.get(url,params=params, verify=False)
    data = json.loads(response.text)
    if 'items' in data and len(data['items']):
        data = data['items']
    else:
        data = []
    # handle errors here later,
    return CommandResults(
        readable_output=data,
        outputs_prefix="PaloAltoIoTIntegrationBase.SingleAlert",
        outputs=data
    )
'''


def get_single_asset(args):
    asset_type = demisto.args().get('asset_type')
    asset_id = demisto.args().get('asset_id')
    params = (
        ('customerid', CUSTOMER_ID),
        ('key_id', KEY_ID),
        ('access_key', ACCESS_KEY),
    )
    if asset_type == 'Devices':
        params += (
            ('detail', 'true'),
            ('deviceid', str(asset_id)),
        )
    if asset_type == 'Alerts':
        params += (
            ('zb_ticketid', str(asset_id)),
        )
    if asset_type == 'Vulnerabilities':
        params += (
            ('groupby', 'device'),
            ('zb_ticketid', str(asset_id)),
        )
    data = []
    url = BASE_URL + api_type_map[asset_type]['single_asset_url']
    response = requests.get(url, params=params, verify=False)
    if response.status_code < 300:
        try:
            data = json.loads(response.text)
            if asset_type == 'Alerts' or asset_type == 'Vulnerabilities':
                data = data['items']
        except Exception as ex:
            return_error("Failed to parse https response %s" % str(ex))
    else:
        return_error("Failed to get asset from IoT server %s" % response.text)

    op = "Total %d %s pulled from PANW IoT Cloud" % (len(data), asset_type)

    return CommandResults(
        readable_output=op,
        outputs_prefix="PaloAltoIoTIntegrationBase.SingleAsset",
        outputs=data
    )


def get_asset_lists(args):
    params = (
        ('customerid', CUSTOMER_ID),
        ('key_id', KEY_ID),
        ('access_key', ACCESS_KEY),
        ('pagelength', str(demisto.args().get('page_size'))),
        ('offset', str(demisto.args().get('offset'))),
    )
    asset_type = demisto.args().get('type')
    if asset_type == 'Devices':
        params += (
            ('detail', 'true'),
        )
    elif asset_type == "Vulnerabilities":
        params += (('groupby', 'device'),)

    data = []
    url = BASE_URL + api_type_map[asset_type]['url']
    response = requests.get(url, params=params, verify=False)

    if response.status_code < 300:
        try:
            data = json.loads(response.text)
            if asset_type == 'Devices' and data['total'] != 0:
                data = data['devices']
            elif asset_type == 'Alerts' or asset_type == 'Vulnerabilities':
                data = data['items']
        except Exception as ex:
            return_error("Failed to parse https response %s" % str(ex))
    else:
        return_error("Failed to connect to IoT server %s" % response.text)

    op = "Total %d %s pulled from PANW IoT Cloud" % (len(data), asset_type)

    return CommandResults(
        readable_output=op,
        outputs_prefix="PaloAltoIoTIntegrationBase.Assets",
        outputs=data
    )


def main() -> None:
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            status, response = run_get_request("Alerts", "pub/v4.0/alert/list")
            if(status == "Success"):
                return_results('ok')
            else:
                return_results(response.status_code)
        elif demisto.command() == 'get-incremental-device-inventory':
            results = run_api_command("Devices", 15)
            return_results(results)
        elif demisto.command() == 'get-incremental-alerts':
            results = run_api_command("Alerts", 15)
            return_results(results)
        elif demisto.command() == 'get-incremental-vulnerabilities':
            results = run_api_command("Vulnerabilities", 15)
            return_results(results)
        elif demisto.command() == 'convert-device-inventory-to-cef':
            results = convert_device_map_to_cef()
            return_results(results)
        elif demisto.command() == 'convert-alerts-to-cef':
            results = convert_alert_map_to_cef()
            return_results(results)
        elif demisto.command() == 'convert-vulnerabilities-to-cef':
            results = convert_vulnerability_map_to_cef()
            return_results(results)
        elif demisto.command() == 'send-status-to-panw-iot-cloud':
            results = send_status_to_iot_cloud()
            return_results(results)
        elif demisto.command() == 'get-servicenow-device-query':
            results = get_servicenow_device_query(demisto.args())
            return_results(results)
        elif demisto.command() == 'get-servicenow-upsert-devices':
            results = get_servicenow_upsert_devices(demisto.args())
            return_results(results)
        elif demisto.command() == 'get-asset-inventory-with-paging-and-offset':
            results = get_asset_lists(demisto.args())
            return_results(results)
        elif demisto.command() == 'get-single-asset-details':
            results = get_single_asset(demisto.args())
            return_results(results)
        elif demisto.command() == 'convert-alert-to-servicenow':
            results = convert_alert_to_servicenow(demisto.args())
            return_results(results)
        elif demisto.command() == 'convert-vulnerability-to-servicenow':
            results = convert_vulnerability_to_servicenow(demisto.args())
            return_results(results)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
