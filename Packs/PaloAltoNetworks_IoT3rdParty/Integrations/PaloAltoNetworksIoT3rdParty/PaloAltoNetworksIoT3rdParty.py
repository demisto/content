from CommonServerPython import *
import urllib3

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

API_TYPE_MAP = {
    "device": {
        "list_url": "pub/v4.0/device/list",
        "single_asset_url": "pub/v4.0/device",
        "context_path": "PanwIot3rdParty.Devices",
    },
    "alert": {
        "list_url": "pub/v4.0/alert/list",
        "single_asset_url": "pub/v4.0/alert",
        "context_path": "PanwIot3rdParty.Alerts",
    },
    "vulnerability": {
        "list_url": "pub/v4.0/vulnerability/list",
        "single_asset_url": "pub/v4.0/vulnerability",
        "context_path": "PanwIot3rdParty.Vulnerabilities",
    }
}

CISCO_ISE_FIELD_MAP = {
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
INT_FIELDS = ["risk_score", "risk score", "confidence", "confidence score", "confidence_score"]

DEVICE_FIELDS_MAP = [
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

VULNERABILITY_FIELDS_MAP = [
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

    params = {
        'customerid': CUSTOMER_ID,
    }
    if api_params is not None:
        params.update(api_params)
    try:
        LOG(f'running {method} request with url={url}')
        response = requests.request(method, url, headers=DEFAULT_HEADERS, params=params, data=data)
    except requests.exceptions.ConnectionError as e:
        err_msg = f'Failed to connect to PANW IoT Cloud. Verify assess_key, key_id and url are correct. {e}'
        raise requests.exceptions.ConnectionError(err_msg)

    if response.status_code not in {200, 201, 202, 204}:
        err_msg = f'Error in API call to PANW IoT Cloud  [{response.status_code}] - {response.reason}'
        raise Exception(err_msg)

    if response.status_code in (201, 204):  # 201-Created OR 204-No Content
        return
    try:
        response = response.json()
    except ValueError:
        err_msg = f'Failed to parse ouput for API call {url}'
        raise ValueError(err_msg)

    return response


def get_asset_list(args):
    """
    Returns a list of assets for the specifed asset type.
    """
    asset_type = args.get('asset_type')
    increment_time = args.get('increment_time')
    page_length = args.get('page_length')
    offset = args.get('offset')

    url = BASE_URL + API_TYPE_MAP[asset_type]['list_url']
    one_call = False
    devices_with_macs = 0
    devices_without_macs = 0

    # if either page_length or offset is set, we dont need to accumulate results
    if page_length or offset:
        one_call = True

    asset_list = []
    poll_time = None  # Device API uses poll time
    stime = None  # Alerts and Vulns use stime

    if page_length is None:
        page_length = DEFAULT_PAGE_SIZE
    if offset is None:
        offset = '0'
    if increment_time is not None:
        if asset_type == "device":
            poll_time = int(round(time.time() * 1000)) - int(increment_time) * 60 * 1000
        else:
            stime = datetime.now() - timedelta(minutes=int(increment_time))

    params = {
        'offset': str(offset),
        'pagelength': str(page_length),
        'stime': stime
    }
    if asset_type == "device":
        params['detail'] = 'true'
        params['last_poll_time'] = str(poll_time)
    elif asset_type == "vulnerability":
        params['groupby'] = 'device'

    # gather all the results, break if the return size is less than requested page size
    while True:
        response = http_request('GET', url, params)
        size = 0
        if asset_type == "device":
            device_list = response.get('devices')
            for device in device_list:
                if "deviceid" in device:
                    deviceid = device['deviceid']
                    if is_mac_address(deviceid):
                        devices_with_macs += 1
                    else:
                        devices_without_macs += 1
            asset_list.extend(device_list)
            size = response.get('total')
        else:
            asset_list.extend(response.get('items'))
            size = len(response.get('items'))
        if one_call or size < int(page_length):
            break
        else:
            new_offset = int(offset) + int(page_length)
            params['offset'] = str(new_offset)
            offset = new_offset

    op_data = {
        "Asset Type": asset_type
    }
    if asset_type == "device":
        op_data['Devices with mac address'] = devices_with_macs
        op_data['Devices without mac address'] = devices_without_macs
    op_data['Total assets pulled'] = len(asset_list)

    return CommandResults(
        readable_output=tableToMarkdown("Asset import summary:", op_data, removeNull=True),
        outputs_prefix=API_TYPE_MAP[asset_type]['context_path'],
        outputs=asset_list
    )


def get_single_asset(args):
    """
    For input asset type and asset ID,
    returns the asset details.
    """

    asset_type = args.get('asset_type')
    asset_id = args.get('asset_id')

    if asset_type is None:
        raise TypeError("Invalid Asset Type")
    if asset_id is None:
        raise TypeError("Invalid Asset ID")

    params = {}
    if asset_type == 'device':
        params['detail'] = 'true'
        params['deviceid'] = str(asset_id)
    elif asset_type == 'alert':
        params['zb_ticketid'] = str(asset_id)
    elif asset_type == 'vulnerability':
        params['groupby'] = 'device'
        params['zb_ticketid'] = str(asset_id)
    else:
        raise TypeError("Invalid Asset Type")

    url = BASE_URL + API_TYPE_MAP[asset_type]['single_asset_url']

    data = http_request('GET', url, params)

    if asset_type in ['alert', 'vulnerability']:
        data = data.get('items')
    msg = f'Successfully pulled {asset_type} ({asset_id}) from PANW IoT Cloud'

    return CommandResults(
        readable_output=msg,
        outputs_prefix="PanwIot3rdParty.SingleAsset",
        outputs=data
    )


def report_status_to_iot_cloud(args):
    """
    Reports status details back to PANW IoT Cloud.
    """
    status = args.get('status')
    message = args.get('message')
    integration_name = args.get('integration_name')
    playbook_name = args.get('playbook_name')
    asset_type = args.get('asset_type')

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

        for t in VULNERABILITY_FIELDS_MAP:
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
        if alert is not None and "msg" in alert and "status" in alert["msg"] and alert["msg"]["status"] == "publish":
            msg = alert['msg']
            line = "CEF:0|PaloAltoNetworks|PANWIOT|1.0|PaloAltoNetworks Alert:policy_alert|"

            if "name" in alert:
                line += alert["name"] + "|"
            if "severityNumber" in alert:
                line += str(alert["severityNumber"]) + "|"
            if "deviceid" in alert:
                line += f'dvcmac={alert["deviceid"]} '
            if "fromip" in msg:
                line += f'src={msg["fromip"]} '
            if "toip" in msg:
                line += f'dst={msg["toip"]} '
            if "hostname" in msg:
                line += f'shost={msg["hostname"]} '
            if "toURL" in msg:
                line += f'dhost={msg["toURL"]} '
            if "id" in msg:
                line += f'fileId={msg["id"]} '
                line += "fileType=alert "

            if "date" in alert:
                line += f'rt={str(alert["date"])} '
            if "generationTimestamp" in msg:
                line += f'deviceCustomDate1={str(msg["generationTimestamp"])} '

            description = None
            values = []
            if "description" in alert:
                description = alert["description"]
            if "values" in msg:
                values = msg["values"]

            line += f'cs1Label=Description cs1={description} '
            line += f'cs2Label=Values cs2={str(values)} '
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
            for t in DEVICE_FIELDS_MAP:
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
            if device_map['mac_address'] is None or device_map['mac_address'] == "":
                continue
            attribute_list = {}
            attribute_list['mac'] = device_map['mac_address']
            zb_attributes = {}
            for field in device_map:
                if device_map[field] is None or device_map[field] == "":
                    continue
                if field in CISCO_ISE_FIELD_MAP:
                    if field in INT_FIELDS:
                        try:
                            int_val = int(device_map[field])
                        except Exception:
                            continue
                        zb_attributes[CISCO_ISE_FIELD_MAP[field][0]] = int_val
                        zb_attributes[CISCO_ISE_FIELD_MAP[field][1]] = int_val
                    else:
                        zb_attributes[CISCO_ISE_FIELD_MAP[field][0]] = device_map[field]
                        zb_attributes[CISCO_ISE_FIELD_MAP[field][1]] = device_map[field]
            attribute_list['zb_attributes'] = zb_attributes
            data.append(attribute_list)

    return data


def convert_alert_to_servicenow(args):
    """
    Converts a PANW IoT alert to ServiceNow table formatted.
    """
    incident = args.get('incident')
    asset_list = args.get('asset_list')
    alert = asset_list[0]
    comments_and_work_notes = str(incident['comments_and_work_notes'])
    url = str(incident['url'])
    urgency = str(incident['urgency'])
    incident.setdefault('user_email', 'cannot find any email')
    # user_email = incident['user_email']
    zb_ticketid = incident['correlation_id']

    alert.setdefault('msg', {}).setdefault('impact', 'Sorry, no impact available to display so far!')
    alert.setdefault('msg', {}).setdefault('recommendation', {}).setdefault(
        'content', ['Sorry, no recommendation available to display so far!'])
    alert.setdefault('location', 'Sorry, location is not provided')
    alert.setdefault('category', 'Sorry, category is not provided')
    alert.setdefault('profile', 'Sorry, profile is not provided')
    alert.setdefault('description', 'Sorry, description is not provided')
    alert.setdefault('name', '')

    impact = alert['msg']['impact']
    recommendations = alert['msg']['recommendation']['content']
    recommendation_text = ''
    alert_description = str(alert['description'])
    category = str(alert['category'])
    profile = str(alert['profile'])
    location = str(alert['location'])
    short_description = str(alert['name'])

    for rec in recommendations:
        recommendation_text += '*' + rec + '\n'

    new_line = '\n'
    description = (
        f'Summary{new_line}{alert_description}{new_line}{new_line}Category: {category} Profile: {profile}'
        f'{new_line}{new_line}Impact{new_line}{impact}{new_line}{new_line}Recommendations{new_line}'
        f'recommendation_text{new_line}URL{new_line}{url}'
    )

    data = (
        f'urgency={urgency};location={location};short_description={short_description};'
        f'comments_and_work_notes={comments_and_work_notes};description={description};'
        f'correlation_id={zb_ticketid};impact=3;company=Palo Alto Networks;opened_by=svc_panw_iot;'
    )

    return data


def convert_vulnerability_to_servicenow(args):
    incident = args.get('incident')
    comments_and_work_notes = str(incident['comments_and_work_notes'])
    url = str(incident['url'])
    urgency = str(incident['urgency'])
    incident.setdefault('user_email', 'cannot find any email')
    # user_email = incident['user_email']
    zb_ticketid = incident['correlation_id']

    asset_list = args.get('asset_list')
    vuln = asset_list[0]
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

    new_line = '\n'
    description = (
        f'Summary{new_line}{alert_description}{new_line}{new_line}Category: {category} Profile: {profile}'
        f'{new_line}{new_line}Impact{new_line}{impact}{new_line}{new_line}Recommendations{new_line}'
        f'recommendation_text{new_line}URL{new_line}{url}'
    )

    data = (
        f'urgency={urgency};location={location};short_description={short_description};'
        f'comments_and_work_notes={comments_and_work_notes};description={description};'
        f'correlation_id={zb_ticketid};impact=3;company=Palo Alto Networks;opened_by=svc_panw_iot;'
    )
    return data


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
            if device[field] is not None:
                value = str(device[field])
        else:
            value = ' '
        fields += (sn_name + "=" + value + ";")
    instance["fields"] = fields

    for field in device_custome_fields_mapping:
        sn_name = device_custome_fields_mapping[field]
        value = ''
        if field in device:
            if device[field] is not None:
                value = str(device[field])
        else:
            value = ' '
        custom_fields += (sn_name + "=" + value + ";")

    instance["custom_fields"] = custom_fields
    return instance


def get_servicenow_upsert_devices(args):
    sn_id_deviceids = {}
    # servicenow_map should be list of ServiceNow table ID and deviceid mapping
    if "servicenow_map" in args:
        sn_id_deviceids = args.get("servicenow_map")
    device_list = args.get("asset_list")
    ids_map = {}
    if sn_id_deviceids:
        for i in range(len(sn_id_deviceids)):
            ids = sn_id_deviceids[i]
            sn_id = ''
            if "ID" in ids:
                sn_id = ids["ID"]
            else:
                sn_id = ids['sys_id']
            deviceid = ids["mac_address"]
            ids_map[deviceid] = sn_id

    update_list = []
    insert_list = []
    for i in range(len(device_list)):
        device = device_list[i]
        deviceid = device["deviceid"]
        instance = convert_device_to_servicenow_format(device)
        if (not ids_map) or (deviceid not in ids_map):
            insert_list.append(instance)
        else:
            sn_id = ids_map[deviceid]
            instance["sys_id"] = sn_id
            update_list.append(instance)

    result = {
        "insert": insert_list,
        "update": update_list,
        "update_count": len(update_list),
        "insert_count": len(insert_list)
    }
    return result


def convert_asset_to_external_format(args):
    """
    For a given asset (alert, device, vuln) converts it
    to specified 3rd party format.
    """

    prefix_map = {
        "device": {
            "SIEM": "PanwIot3rdParty.DeviceCEFSyslogs",
            "CiscoISECustomAttributes": "PanwIot3rdParty.CiscoISEAttributes",
            "ServiceNow": "PanwIot3rdParty.DeviceServiceNow"
        },
        "alert": {
            "SIEM": "PanwIot3rdParty.AlertCEFSyslogs",
            "ServiceNow": "PanwIot3rdParty.AlertServiceNow"
        },
        "vulnerability": {
            "SIEM": "PanwIot3rdParty.VulnerabilityCEFSyslogs",
            "ServiceNow": "PanwIot3rdParty.VulnerabilityServiceNow"
        }
    }

    asset_type = args.get('asset_type')
    output_format = args.get('output_format')
    asset_list = args.get('asset_list')
    data = []
    readable_res = ''

    if output_format == "ServiceNow":
        if asset_list:
            if asset_type == "device":
                data = get_servicenow_upsert_devices(args)
                readable_res = f'Converted Device list to {len(data)} upsert {output_format} list'
            elif asset_type == 'alert':
                data = convert_alert_to_servicenow(args)
                correlation_id = args.get('incident')['correlation_id']
                readable_res = f'Converted Alert {correlation_id} to {output_format}'
            elif asset_type == 'vulnerability':
                data = convert_vulnerability_to_servicenow(args)
                correlation_id = args.get('incident')['correlation_id']
                readable_res = f'Converted Vulnerability {correlation_id} to {output_format}'
        else:
            err_msg = f'Output format ServiceNow not supported for {asset_type}'
            raise TypeError(err_msg)

    elif output_format == "SIEM":
        if asset_list:
            if asset_type == "device":
                data = convert_device_list_to_cef(asset_list)
            elif asset_type == 'alert':
                data = convert_alert_list_to_cef(asset_list)
            elif asset_type == "vulnerability":
                data = convert_vulnerability_list_to_cef(asset_list)
            else:
                err_msg = f'Output format SIEM not supported for {asset_type}'
                raise TypeError(err_msg)
        readable_res = f'Converted {len(data)} {asset_type} to {output_format}'

    elif output_format == 'CiscoISECustomAttributes':
        if asset_list:
            if asset_type == 'device':
                data = convert_device_list_to_ise_attributes(asset_list)
            else:
                err_msg = f'Output format CiscoISECustomAttributes not supported for {asset_type}'
                raise TypeError(err_msg)
        readable_res = f'Converted {len(data)} {asset_type} to {output_format}'

    prefix = prefix_map[asset_type][output_format]

    return CommandResults(
        readable_output=readable_res,
        outputs_prefix=prefix,
        outputs=data
    )


def connection_test_command() -> str:
    """
    Try to get a single device from the Cloud to test connectivity.
    """
    params = {
        'offset': '0',
        'pagelength': '1',
        'detail': 'false',
    }
    url = f"{BASE_URL}{API_TYPE_MAP['device']['list_url']}"
    http_request('GET', url, params)

    return 'ok'


def main() -> None:
    """main function, parses args and runs command functions
    """
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f'Command being called is {command}')
    try:
        if command == 'test-module':
            return_results(connection_test_command())
        elif command == 'panw-iot-3rd-party-get-asset-list':
            results = get_asset_list(args)
            return_results(results)
        elif command == 'panw-iot-3rd-party-get-single-asset':
            results = get_single_asset(args)
            return_results(results)
        elif command == 'panw-iot-3rd-party-report-status-to-panw':
            results = report_status_to_iot_cloud(args)
            return_results(results)
        elif command == 'panw-iot-3rd-party-convert-assets-to-external-format':
            results = convert_asset_to_external_format(args)
            return_results(results)
        # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
