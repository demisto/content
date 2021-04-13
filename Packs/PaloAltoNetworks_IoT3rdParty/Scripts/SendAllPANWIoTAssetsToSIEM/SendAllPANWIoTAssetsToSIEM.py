import demistomock as demisto
from CommonServerPython import *
SIEM_INSTANCE = demisto.args().get('syslog_sender_instance')
PANW_IOT_INSTANCE = demisto.args().get('panw_iot_3rd_party_instance')

VULNERABILITIES_FIELDS_MAP = [
    ("ip", "dvc="),
    ("deviceid", "dvcmac="),
    ("name", "dvchost="),
    ("profile", "cs1Label=Profile cs1="),
    ("display_profile_category", "cs2Label=Category cs2="),
    ("profile_vertical", "cs3Label=ProfileVertical cs3="),
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

DEVICE_FIELDS_MAP = [
    ("ip_address", "dvc="),
    ("mac_address", "dvcmac="),
    ("hostname", "dvchost="),
    ("profile", "cs1Label=Profile cs1="),
    ("category", "cs2Label=Category cs2="),
    ("profile_type", "cs3Label=ProfileType cs3="),
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


def convert_device_map_to_cef(device_map):
    """
    Converts a PANW IoT device map to CEF syslog format.
    param device_map: PANW IoT device map containing device attributes
    """
    cef = "INFO:siem-syslog:CEF:0|PaloAltoNetworks|PANWIOT|1.0|asset|Asset Identification|1|"
    for t in DEVICE_FIELDS_MAP:
        input_field = t[0]
        output_field = t[1]
        if input_field in device_map:
            val = device_map[input_field]
        else:
            val = ""
        if output_field and val:
            cef += str(output_field) + str(val) + " "
    return cef


def convert_alert_to_cef(alert):
    """
    Converts a PANW IoT alert to CEF syslog format.
    param alert: PANW IoT alert containing alert attributes
    """
    if alert is not None and "msg" in alert and "status" in alert["msg"] and alert["msg"]["status"] == "publish":
        msg = alert['msg']
        cef = "CEF:0|PaloAltoNetworks|PANWIOT|1.0|PaloAltoNetworks Alert:policy_alert|"

        if "name" in alert:
            cef += alert["name"] + "|"
        if "severityNumber" in alert:
            cef += str(alert["severityNumber"]) + "|"
        if "deviceid" in alert:
            cef += "dvcmac=%s " % alert["deviceid"]
        if "fromip" in msg:
            cef += "src=%s " % msg["fromip"]
        if "toip" in msg:
            cef += "dst=%s " % msg["toip"]
        if "hostname" in msg:
            cef += "shost=%s " % msg["hostname"]
        if "toURL" in msg:
            cef += "dhost=%s " % msg["toURL"]
        if "id" in msg:
            cef += "fileId=%s " % msg["id"]
            cef += "fileType=alert "

        if "date" in alert:
            cef += "rt=%s " % str(msg["id"])
        if "generationTimestamp" in msg:
            cef += "deviceCustomDate1=%s " % str(msg["generationTimestamp"])

        description = None
        values = []
        if "description" in alert:
            description = alert["description"]
        if "values" in msg:
            values = msg["values"]

        cef += "cs1Label=Description cs1=%s " % description
        cef += "cs2Label=Values cs2=%s " % str(values)
        return cef
    else:
        return None


def convert_vulnerability_to_cef(vulnerability):
    """
    Converts a PANW IoT vulnerability to CEF syslog format.
    param device_map: PANW IoT vulnerability containing vulnerability attributes
    """
    risk_level_map = {'Critical': '10', 'High': '6', 'Medium': '3', 'Low': '1'}
    cef = "INFO:siem-syslog:CEF:0|PaloAltoNetworks|PANWIOT|1.0|vulnerability|"
    if "vulnerability_name" in vulnerability:
        cef += vulnerability['vulnerability_name'] + "|"
    if "risk_level" in vulnerability:
        if vulnerability["risk_level"] in risk_level_map:
            cef += risk_level_map[vulnerability["risk_level"]] + "|"
        else:
            cef += "1|"  # default severity

    for t in VULNERABILITIES_FIELDS_MAP:
        input_field = t[0]
        output_field = t[1]
        # print input_field, output_field
        if input_field in vulnerability:
            val = vulnerability[input_field]
        else:
            val = ""
        if output_field and val:
            cef += str(output_field) + str(val) + " "
    return cef


def convert_single_asset_to_cef(asset, asset_type):
    """
    Converts the given asset of type asset_type to CEF syslog format.
    param asset: Single PANW IoT cloud discovered asset.
    param asset_type: type of asset (device, alert or vulnerability).
    """
    if asset_type == 'alert':
        return convert_alert_to_cef(asset)
    elif asset_type == 'vulnerability':
        return convert_vulnerability_to_cef(asset)
    else:
        return convert_device_map_to_cef(asset)


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
        for asset in asset_list:
            cef = convert_single_asset_to_cef(asset, asset_type)
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
