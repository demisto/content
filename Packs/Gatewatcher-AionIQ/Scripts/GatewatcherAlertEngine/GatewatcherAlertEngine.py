import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import json
from typing import Any


def gatewatcherAlertEngine() -> CommandResults:

    incident = demisto.incident()
    d = json.loads(str(incident['CustomFields']['GatewatcherRawEvent']))
    ret_fields: dict[Any, Any] = {}

    if d['event']['module'] == "active_cti":

        ret_fields = {
            "dns.query": d.get('dns', {}).get('query', []),
            "flow.bytes_toclient": d.get('flow', {}).get('bytes_toclient', 0),
            "flow.bytes_toserver": d.get('flow', {}).get('bytes_toserver', 0),
            "flow.pkts_toclient": d.get('flow', {}).get('pkts_toclient', 0),
            "flow.pkts_toserver": d.get('flow', {}).get('pkts_toserver', 0),
            "flow.start": d.get('flow', {}).get('start', ""),
            "sigflow.action": d.get('sigflow', {}).get('action', ""),
            "sigflow.category": d.get('sigflow', {}).get('category', ""),
            "sigflow.gid": d.get('sigflow', {}).get('gid', 0),
            "sigflow.metadata": d.get('sigflow', {}).get('metadata', {}),
            "sigflow.payload": d.get('sigflow', {}).get('payload', ""),
            "sigflow.payload_printable": d.get('sigflow', {}).get('payload_printable', ""),
            "sigflow.rev": d.get('sigflow', {}).get('rev', 0),
            "sigflow.signature": d.get('sigflow', {}).get('signature', ""),
            "sigflow.signature_id": d.get('sigflow', {}).get('signature_id', 0),
            "sigflow.stream": d.get('sigflow', {}).get('stream', 0)
        }

    if d['event']['module'] == "malcore":

        ret_fields = {
            "malcore.analyzed_clean": d['malcore'].get("analyzed_clean", 0),
            "malcore.analyzed_error": d['malcore'].get("analyzed_error", 0),
            "malcore.analyzed_infected": d['malcore'].get("analyzed_infected", 0),
            "malcore.analyzed_other": d['malcore'].get("analyzed_other", 0),
            "malcore.analyzed_suspicious": d['malcore'].get("analyzed_suspicious", 0),
            "malcore.analyzers_up": d['malcore'].get("analyzers_up", 0),
            "malcore.code": d['malcore'].get("code", 0),
            "malcore.detail_scan_time": d['malcore'].get("detail_scan_time", 0),
            "malcore.detail_threat_found": d['malcore'].get("detail_threat_found", ""),
            "malcore.detail_wait_time": d['malcore'].get("detail_wait_time", 0),
            "malcore.engine_id": d['malcore'].get("engine_id", {}),
            "malcore.engines_last_update_date": d['malcore'].get("engines_last_update_date", ""),
            "malcore.file_type": d['malcore'].get("file_type", ""),
            "malcore.file_type_description": d['malcore'].get("file_type_description", ""),
            "malcore.magic_details": d['malcore'].get("magic_details", ""),
            "malcore.processing_time": d['malcore'].get("processing_time", 0),
            "malcore.reporting_token": d['malcore'].get("reporting_token", ""),
            "malcore.state": d['malcore'].get("state", ""),
            "malcore.total_found": d['malcore'].get("total_found", "")
        }

    if d['event']['module'] == "malcore_retroanalyzer":

        ret_fields = {
            "malcore_retroanalyzer.analyzed_clean": d['malcore_retroanalyzer'].get("analyzed_clean", 0),
            "malcore_retroanalyzer.analyzed_error": d['malcore_retroanalyzer'].get("analyzed_error", 0),
            "malcore_retroanalyzer.analyzed_infected": d['malcore_retroanalyzer'].get("analyzed_infected", 0),
            "malcore_retroanalyzer.analyzed_other": d['malcore_retroanalyzer'].get("analyzed_other", 0),
            "malcore_retroanalyzer.analyzed_suspicious": d['malcore_retroanalyzer'].get("analyzed_suspicious", 0),
            "malcore_retroanalyzer.analyzers_up": d['malcore_retroanalyzer'].get("analyzers_up", 0),
            "malcore_retroanalyzer.code": d['malcore_retroanalyzer'].get("code", 0),
            "malcore_retroanalyzer.detail_scan_time": d['malcore_retroanalyzer'].get("detail_scan_time", 0),
            "malcore_retroanalyzer.detail_threat_found": d['malcore_retroanalyzer'].get("detail_threat_found", ""),
            "malcore_retroanalyzer.detail_wait_time": d['malcore_retroanalyzer'].get("detail_wait_time", 0),
            "malcore_retroanalyzer.engine_id": d['malcore_retroanalyzer'].get("engine_id", {}),
            "malcore_retroanalyzer.engines_last_update_date": d['malcore_retroanalyzer'].get("engines_last_update_date", ""),
            "malcore_retroanalyzer.file_type": d['malcore_retroanalyzer'].get("file_type", ""),
            "malcore_retroanalyzer.file_type_description": d['malcore_retroanalyzer'].get("file_type_description", ""),
            "malcore_retroanalyzer.magic_details": d['malcore_retroanalyzer'].get("magic_details", ""),
            "malcore_retroanalyzer.processing_time": d['malcore_retroanalyzer'].get("processing_time", 0),
            "malcore_retroanalyzer.reporting_token": d['malcore_retroanalyzer'].get("reporting_token", ""),
            "malcore_retroanalyzer.state": d['malcore_retroanalyzer'].get("state", ""),
            "malcore_retroanalyzer.total_found": d['malcore_retroanalyzer'].get("total_found", "")
        }

    if d['event']['module'] == "shellcode_detect":

        ret_fields = {
            "shellcode.analysis": d['shellcode'].get("analysis", {}),
            "shellcode.encodings": d['shellcode'].get("encodings", []),
            "shellcode.id": d['shellcode'].get("id", ""),
            "shellcode.sample_id": d['shellcode'].get("sample_id", ""),
            "shellcode.sub_type": d['shellcode'].get("sub_type", "")
        }

    if d['event']['module'] == "malicious_powershell_detect":

        ret_fields = {
            "malicious_powershell.id": d['malicious_powershell'].get("id", ""),
            "malicious_powershell.proba_obfuscated": d['malicious_powershell'].get("proba_obfuscated", 0),
            "malicious_powershell.sample_id": d['malicious_powershell'].get("sample_id", ""),
            "malicious_powershell.score": d['malicious_powershell'].get("score", 0),
            "malicious_powershell.score_details": d['malicious_powershell'].get("score_details", {})
        }

    if d['event']['module'] == "sigflow_alert":

        ret_fields = {
            "sigflow.action": d['sigflow'].get("action", ""),
            "sigflow.category": d['sigflow'].get("category", ""),
            "sigflow.gid": d['sigflow'].get("gid", 0),
            "sigflow.metadata": d['sigflow'].get('metadata', {}),
            "sigflow.payload": d['sigflow'].get("payload", ""),
            "sigflow.payload_printable": d['sigflow'].get("payload_printable", ""),
            "sigflow.rev": d['sigflow'].get("rev", 0),
            "sigflow.signature": d['sigflow'].get("signature", ""),
            "sigflow.signature_id": d['sigflow'].get("signature_id", 0),
            "sigflow.stream": d['sigflow'].get("stream", 0)
        }

    if d['event']['module'] == "dga_detect":

        ret_fields = {
            "dga.dga_count": d['dga'].get("dga_count", 0),
            "dga.dga_ratio": d['dga'].get("dga_ratio", 0),
            "dga.malware_behavior_confidence": d['dga'].get("malware_behavior_confidence", 0),
            "dga.nx_domain_count": d['dga'].get("nx_domain_count", 0),
            "dga.top_DGA": d['dga'].get("top_DGA", [])
        }

    if d['event']['module'] == "ioc":

        ret_fields = {
            "ioc.campaigns": d['ioc'].get("campaigns", []),
            "ioc.case_id": d['ioc'].get("case_id", ""),
            "ioc.categories": d['ioc'].get("categories", []),
            "ioc.creation_date": d['ioc'].get("creation_date", ""),
            "ioc.description": d['ioc'].get("description", ""),
            "ioc.external_links": d['ioc'].get("external_links", []),
            "ioc.families": d['ioc'].get("families", []),
            "ioc.id": d['ioc'].get("id", ""),
            "ioc.kill_chain_phases": d['ioc'].get("kill_chain_phases", []),
            "ioc.meta_data": d['ioc'].get("meta_data", {}),
            "ioc.package_date": d['ioc'].get("package_date", ""),
            "ioc.relations": d['ioc'].get("relations", []),
            "ioc.signature": d['ioc'].get("signature", ""),
            "ioc.tags": d['ioc'].get("tags", []),
            "ioc.targeted_countries": d['ioc'].get("targeted_countries", []),
            "ioc.targeted_organizations": d['ioc'].get("targeted_organizations", []),
            "ioc.targeted_platforms": d['ioc'].get("targeted_platforms", []),
            "ioc.targeted_sectors": d['ioc'].get("targeted_sectors", []),
            "ioc.threat_actor": d['ioc'].get("threat_actor", []),
            "ioc.tlp": d['ioc'].get("tlp", ""),
            "ioc.ttp": d['ioc'].get("ttp", []),
            "ioc.type": d['ioc'].get("type", ""),
            "ioc.updated_date": d['ioc'].get("updated_date", ""),
            "ioc.usage_mode": d['ioc'].get("usage_mode", ""),
            "ioc.value": d['ioc'].get("value", ""),
            "ioc.vulnerabilities": d['ioc'].get("vulnerabilities", [])
        }

    if d['event']['module'] == "ransomware_detect":

        ret_fields = {
            "ransomware.alert_threshold": d['ransomware'].get("alert_threshold", 0),
            "ransomware.malicious_behavior_confidence": d['ransomware'].get("malicious_behavior_confidence", 0),
            "ransomware.session_score": d['ransomware'].get("session_score", 0)
        }

    if d['event']['module'] == "beacon_detect":

        ret_fields = {
            "beacon.active": d['beacon'].get("active", ""),
            "beacon.hostname_resolution": d['beacon'].get("hostname_resolution", ""),
            "beacon.id": d['beacon'].get("id", ""),
            "beacon.mean_time_interval": d['beacon'].get("mean_time_interval", 0),
            "beacon.possible_cnc": d['beacon'].get("possible_cnc", ""),
            "beacon.session_count": d['beacon'].get("session_count", 0),
            "beacon.type": d['beacon'].get("type", "")
        }

    if d['event']['module'] == "retrohunt":

        ret_fields = {
            "ioc.campaigns": d.get("ioc", {}).get("campaigns", []),
            "ioc.case_id": d.get("ioc", {}).get("case_id", ""),
            "ioc.categories": d.get("ioc", {}).get("categories", []),
            "ioc.creation_date": d.get("ioc", {}).get("creation_date", ""),
            "ioc.description": d.get("ioc", {}).get("description", ""),
            "ioc.external_links": d.get("ioc", {}).get("external_links", []),
            "ioc.families": d.get("ioc", {}).get("families", []),
            "ioc.id": d.get("ioc", {}).get("id", ""),
            "ioc.kill_chain_phases": d.get("ioc", {}).get("kill_chain_phases", []),
            "ioc.meta_data": d.get("ioc", {}).get("meta_data", {}),
            "ioc.package_date": d.get("ioc", {}).get("package_date", ""),
            "ioc.relations": d.get("ioc", {}).get("relations", []),
            "ioc.signature": d.get("ioc", {}).get("signature", ""),
            "ioc.tags": d.get("ioc", {}).get("tags", []),
            "ioc.targeted_countries": d.get("ioc", {}).get("targeted_countries", []),
            "ioc.targeted_organizations": d.get("ioc", {}).get("targeted_organizations", []),
            "ioc.targeted_platforms": d.get("ioc", {}).get("targeted_platforms", []),
            "ioc.targeted_sectors": d.get("ioc", {}).get("targeted_sectors", []),
            "ioc.threat_actor": d.get("ioc", {}).get("threat_actor", []),
            "ioc.tlp": d.get("ioc", {}).get("tlp", ""),
            "ioc.ttp": d.get("ioc", {}).get("ttp", []),
            "ioc.type": d.get("ioc", {}).get("type", ""),
            "ioc.updated_date": d.get("ioc", {}).get("updated_date", ""),
            "ioc.usage_mode": d.get("ioc", {}).get("usage_mode", ""),
            "ioc.value": d.get("ioc", {}).get("value", ""),
            "ioc.vulnerabilities": d.get("ioc", {}).get("vulnerabilities", []),
            "matched_event.content": d['matched_event'].get("content", {}),
            "matched_event.id": d['matched_event'].get("id", "")
        }

    return CommandResults(raw_response=ret_fields)


def main():
    try:
        return_results(gatewatcherAlertEngine())

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Gate. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
