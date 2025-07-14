import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

def get_module_command(module: str, user: str) -> tuple[str, dict]:
    return {
        "Active Directory Query v2": ("ad-disable-account", {"username": user}),
        "Microsoft Graph User": ("msgraph-user-account-disable", {"user": user}),
        "Okta v2": ("okta-suspend-user", {"username": user}),
        "Okta IAM": ("iam-disable-user", {"user-profile": user}),
        "AWS-ILM": ("iam-disable-user", {"user-profile": user}),
        "GSuiteAdmin": ("gsuite-user-update", {"user_key": user, "suspended": "true"})
    }[module]

def validate_input(args: dict): ...

def get_users(args: dict) -> list[str]: ...

def get_commands(brands: str | list[str], instances: str | list[str]) -> list[tuple[str, str]]: ...

def run_commands(TBD): ...

def main():
    try:
        demisto.getModules()
        {
            "WildFire-Reports_default_instance": {
                "category": "Forensics & Malware Analysis", 
                "defaultIgnored": "false", 
                "brand": "WildFire-Reports", 
                "state": "active"
            }, 
            "Cortex XDR - IR_instance_1": {
                "category": "Endpoint", 
                "defaultIgnored": "true", 
                "brand": "Cortex XDR - IR", 
                "state": "disabled"
            }, 
            "testmodule": {
                "category": "Data Enrichment & Threat Intelligence", 
                "defaultIgnored": "false", 
                "brand": "testmodule", 
                "state": "active"
            }, 
            "fcm_default_instance": {
                "category": "Messaging", 
                "defaultIgnored": "false", 
                "brand": "fcm", 
                "state": "active"
            }, 
            "Rasterize_default_instance": {
                "category": "Utilities", 
                "defaultIgnored": "false", 
                "brand": "Rasterize", 
                "state": "active"
            }, 
            "Google IP Ranges Feed_instance_1": {
                "category": "Data Enrichment & Threat Intelligence", 
                "defaultIgnored": "false", 
                "brand": "Google IP Ranges Feed", 
                "state": "disabled"
            }, 
            "ThreatGridv2_instance_1": {
                "category": "Forensics & Malware Analysis", 
                "defaultIgnored": "false", 
                "brand": "ThreatGridv2", 
                "state": "active"
            }, 
            "AutoFocusTagsFeed_default_instance": {
                "category": "Data Enrichment & Threat Intelligence", 
                "defaultIgnored": "false", 
                "brand": "AutoFocusTagsFeed", 
                "state": "disabled"
            }, 
            "SplunkPy_instance_1": {
                "category": "Analytics & SIEM", 
                "defaultIgnored": "false", 
                "brand": "SplunkPy", 
                "state": "active"
            }, 
            "Panorama v8": {
                "category": "Network Security", 
                "defaultIgnored": "false", 
                "brand": "Panorama", 
                "state": "disabled"
            }, 
            "CustomScripts": {
                "category": "automation", 
                "defaultIgnored": "false", 
                "brand": "Scripts", 
                "state": "active"
            }, 
            "Image OCR_default_instance": {
                "category": "Utilities", 
                "defaultIgnored": "false", 
                "brand": "Image OCR", 
                "state": "active"
            }, 
            "AzureFeed_instance_1": {
                "category": "Data Enrichment & Threat Intelligence", 
                "defaultIgnored": "false", 
                "brand": "AzureFeed", 
                "state": "active"
            }, 
            "FW v11": {
                "category": "Network Security", 
                "defaultIgnored": "false", 
                "brand": "Panorama", 
                "state": "disabled"
            }, 
            "Panorama v11": {
                "category": "Network Security", 
                "defaultIgnored": "false", 
                "brand": "Panorama", 
                "state": "active"
            }, 
            "InnerServicesModule": {
                "category": "Builtin", 
                "defaultIgnored": "false", 
                "brand": "Builtin", 
                "state": "active"
            }, 
            "Whois_instance_1": {
                "category": "Data Enrichment & Threat Intelligence", 
                "defaultIgnored": "false", 
                "brand": "Whois", 
                "state": "active"
            }, 
            "Proofpoint TAP v2_instance_1": {
                "category": "Email", 
                "defaultIgnored": "false", 
                "brand": "Proofpoint TAP v2", 
                "state": "disabled"
            }
        }
        return_outputs(demisto.args())
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute DisableUser. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
