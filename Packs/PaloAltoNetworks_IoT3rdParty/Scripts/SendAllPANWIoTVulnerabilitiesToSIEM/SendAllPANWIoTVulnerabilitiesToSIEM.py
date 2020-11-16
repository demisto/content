import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
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


SIEM_INSTANCE = "PANW IoT 3rd Party SIEM Integration Instance"
PANW_IOT_INSTANCE = "PANW IoT 3rd Party Integration Instance"

'''
returns a status and message back to cloud
'''


def send_status_to_panw_iot_cloud(status=None, msg=None):
    demisto.executeCommand("panw-iot-3rd-party-report-status-to-panw", {
        "status": status,
        "message": msg,
        "integration-name": "siem",
        "playbook-name": "PANW IoT 3rd Party SIEM Integration - Bulk Export to SIEM",
        "type": "vulnerability",
        "timestamp": int(round(time.time() * 1000)),
        "using": PANW_IOT_INSTANCE
    })


count = 0
PAGE_SIZE = 1000
offset = 0

while True:
    resp = demisto.executeCommand("panw-iot-3rd-party-get-asset-list", {
        "assetType": "Vulnerability",
        "incrementTime": None,
        "offset": offset,
        "pageLength": PAGE_SIZE,
        "using": PANW_IOT_INSTANCE

    })
    if isError(resp[0]):
        err_msg = "Error, could not get Vulnerabilities from Iot Cloud %s" % resp[0].get('Contents')
        send_status_to_panw_iot_cloud("error", err_msg)
        demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % err_msg)
        return_error(err_msg)
        break
    size = 0
    risk_level_map = {'Critical': '10', 'High': '6', 'Medium': '3', 'Low': '1'}
    try:
        vulnerability_list = resp[0]['Contents']
        size = len(vulnerability_list)
        for vulnerability in vulnerability_list:
            cef = "INFO:siem-syslog:CEF:0|PaloAltoNetworks|PANWIOT|1.0|vulnerability|"
            if "vulnerability_name" in vulnerability:
                cef += vulnerability['vulnerability_name'] + "|"
            if "risk_level" in vulnerability:
                if vulnerability["risk_level"] in risk_level_map:
                    cef += risk_level_map[vulnerability["risk_level"]] + "|"
                else:
                    cef += "1|"  # default severity

            for t in vulnerabilities_fields_map:
                input_field = t[0]
                output_field = t[1]
                # print input_field, output_field
                if input_field in vulnerability:
                    val = vulnerability[input_field]
                else:
                    val = ""
                if output_field and val:
                    cef += str(output_field) + str(val) + " "

            res = demisto.executeCommand("syslog-send", {"message": cef, "using": SIEM_INSTANCE})
            if isError(res[0]):
                    # We only get an error is configured syslog server address cant be resolved
                err_msg = "Cant connect to SIEM server %s" % res[0].get('Contents')
                send_status_to_panw_iot_cloud("error", err_msg)
                return_error(err_msg)
            else:
                count += 1

    except Exception as ex:
        return_error("Failed to parse vulernability map %s" % str(ex))

    if size == PAGE_SIZE:
        offset += PAGE_SIZE
        msg = "Successfully sent %d Vulnerabilities to SIEM" % count
        send_status_to_panw_iot_cloud("success", msg)
        demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % msg)
        time.sleep(3)
    else:
        break

msg = "Successfully sent total %d Vulnerabilities to SIEM" % count
send_status_to_panw_iot_cloud("success", msg)
demisto.info("PANW_IOT_3RD_PARTY_BASE %s" % msg)
return_results(msg)
