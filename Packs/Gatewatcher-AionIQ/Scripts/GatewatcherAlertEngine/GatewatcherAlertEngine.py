import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import json


def gatewatcherAlertEngine() -> CommandResults:

    incident = demisto.incident()
    d = json.loads(str(incident['CustomFields']['GatewatcherRawEvent']))

    if d['event']['module'] == "malcore":

        ret_fields = {
            "malcore.detail_threat_found": "",
            "malcore.engines_last_update_date": "",
            "malcore.magic_details": "",
            "malcore.state": "",
            "malcore.total_found": ""
        }
        ret_fields['malcore.detail_threat_found'] = d['malcore']['detail_threat_found']
        ret_fields['malcore.engines_last_update_date'] = d['malcore']['engines_last_update_date']
        ret_fields['malcore.magic_details'] = d['malcore']['magic_details']
        ret_fields['malcore.state'] = d['malcore']['state']
        ret_fields['malcore.total_found'] = d['malcore']['total_found']

    if d['event']['module'] == "shellcode_detect":

        ret_fields = {
            "shellcode.encodings": "",
            "shellcode.sub_type": ""
        }
        ret_fields['shellcode.encodings'] = d['shellcode']['encodings']
        ret_fields['shellcode.sub_type'] = d['shellcode']['sub_type']

    if d['event']['module'] == "malicious_powershell_detect":

        ret_fields = {
            "malicious_powershell.proba_obfuscated": "",
            "malicious_powershell.score": ""
        }
        ret_fields['malicious_powershell.proba_obfuscated'] = d['malicious_powershell']['proba_obfuscated']
        ret_fields['malicious_powershell.score'] = d['malicious_powershell']['score']

    if d['event']['module'] == "sigflow_alert":

        ret_fields = {
            "sigflow.action": "",
            "sigflow.category": "",
            "sigflow.payload": "",
            "sigflow.payload_printable": ""
        }
        ret_fields['sigflow.action'] = d['sigflow']['action']
        ret_fields['sigflow.category'] = d['sigflow']['category']
        ret_fields['sigflow.payload'] = d['sigflow']['payload']
        ret_fields['sigflow.payload_printable'] = d['sigflow']['payload_printable']

    if d['event']['module'] == "dga_detect":

        ret_fields = {
            "dga.dga_count": "",
            "dga.dga_ratio": "",
            "dga.malware_behavior_confidence": "",
            "dga.nx_domain_count": "",
            "dga.top_DGA": ""
        }
        ret_fields['dga.dga_count'] = d['dga']['dga_count']
        ret_fields['dga.dga_ratio'] = d['dga']['dga_ratio']
        ret_fields['dga.malware_behavior_confidence'] = d['dga']['malware_behavior_confidence']
        ret_fields['dga.nx_domain_count'] = d['dga']['nx_domain_count']
        ret_fields['dga.top_DGA'] = d['dga']['top_DGA']

    if d['event']['module'] == "ioc":

        ret_fields = {
            "ioc.campaigns": "",
            "ioc.case_id": "",
            "ioc.categories": "",
            "ioc.creation_date": "",
            "ioc.description": "",
            "ioc.external_links": "",
            "ioc.families": "",
            "ioc.kill_chain_phases": "",
            "ioc.meta_data": "",
            "ioc.package_date": "",
            "ioc.relations": "",
            "ioc.signature": "",
            "ioc.tags": "",
            "ioc.targeted_countries": "",
            "ioc.targeted_organizations": "",
            "ioc.targeted_platforms": "",
            "ioc.targeted_sectors": "",
            "ioc.threat_actor": "",
            "ioc.tlp": "",
            "ioc.ttp": "",
            "ioc.type": "",
            "ioc.updated_date": "",
            "ioc.usage_mode": "",
            "ioc.value": "",
            "ioc.vulnerabilities": "",
        }
        ret_fields['ioc.campaigns'] = d['ioc']['campaigns']
        ret_fields['ioc.case_id'] = d['ioc']['case_id']
        ret_fields['ioc.categories'] = d['ioc']['categories']
        ret_fields['ioc.creation_date'] = d['ioc']['creation_date']
        ret_fields['ioc.description'] = d['ioc']['description']
        ret_fields['ioc.external_links'] = d['ioc']['external_links']
        ret_fields['ioc.families'] = d['ioc']['families']
        ret_fields['ioc.kill_chain_phases'] = d['ioc']['kill_chain_phases']
        ret_fields['ioc.meta_data'] = d['ioc']['meta_data']
        ret_fields['ioc.package_date'] = d['ioc']['package_date']
        ret_fields['ioc.relations'] = d['ioc']['relations']
        ret_fields['ioc.signature'] = d['ioc']['signature']
        ret_fields['ioc.tags'] = d['ioc']['tags']
        ret_fields['ioc.targeted_countries'] = d['ioc']['targeted_countries']
        ret_fields['ioc.targeted_organizations'] = d['ioc']['targeted_organizations']
        ret_fields['ioc.targeted_platforms'] = d['ioc']['targeted_platforms']
        ret_fields['ioc.targeted_sectors'] = d['ioc']['targeted_sectors']
        ret_fields['ioc.threat_actor'] = d['ioc']['threat_actor']
        ret_fields['ioc.tlp'] = d['ioc']['tlp']
        ret_fields['ioc.ttp'] = d['ioc']['ttp']
        ret_fields['ioc.type'] = d['ioc']['type']
        ret_fields['ioc.updated_date'] = d['ioc']['updated_date']
        ret_fields['ioc.usage_mode'] = d['ioc']['usage_mode']
        ret_fields['ioc.value'] = d['ioc']['value']
        ret_fields['ioc.vulnerabilities'] = d['ioc']['vulnerabilities']

    if d['event']['module'] == "ransomware_detect":

        ret_fields = {
            "ransomware.alert_threshold": "",
            "ransomware.malicious_behavior_confidence": "",
            "ransomware.session_score": ""
        }
        ret_fields['ransomware.alert_threshold'] = d['ransomware']['alert_threshold']
        ret_fields['ransomware.malicious_behavior_confidence'] = d['ransomware']['malicious_behavior_confidence']
        ret_fields['ransomware.session_score'] = d['ransomware']['session_score']

    if d['event']['module'] == "beacon_detect":

        ret_fields = {
            "beacon.active": "",
            "beacon.hostname_resolution": "",
            "beacon.id": "",
            "beacon.mean_time_interval": "",
            "beacon.possible_cnc": "",
            "beacon.session_count": "",
            "beacon.type": ""
        }
        ret_fields['beacon.active'] = d['beacon']['active']
        ret_fields['beacon.hostname_resolution'] = d['beacon']['hostname_resolution']
        ret_fields['beacon.id'] = d['beacon']['id']
        ret_fields['beacon.mean_time_interval'] = d['beacon']['mean_time_interval']
        ret_fields['beacon.possible_cnc'] = d['beacon']['possible_cnc']
        ret_fields['beacon.session_count'] = d['beacon']['session_count']
        ret_fields['beacon.type'] = d['beacon']['type']

    return CommandResults(raw_response=ret_fields)


def main():
    try:
        return_results(gatewatcherAlertEngine())

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Gate. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
