# CheckFirewallAndGPForCVEs

This script checks if PAN-OS firewall and GlobalProtect versions are affected by specific CVEs (Common Vulnerabilities and Exposures).

## Description

The script analyzes firewall system information against CVE data to determine if the current PAN-OS software version or GlobalProtect client package version is vulnerable to known security issues. It implements the CVE schema algorithm for version comparison and status determination.

## Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pan_os_system_info_list | System info of firewalls (array). Output of pan-os-platform-get-system-info command | Required |
| cve_json | List of CVE with detailed json (array). Output of PAN_OS_Security_Advisories_Enrichment script | Required |

### pan_os_system_info_list Format

Each firewall entry should contain:

- `hostname`: Firewall hostname
- `ip_address`: Firewall IP address  
- `sw_version`: PAN-OS software version
- `global_protect_client_package_version`: GlobalProtect client version (optional)

### cve_json Format

Each CVE entry should contain:

- `cve_id`: CVE identifier
- `cvethreatseverity` or `cvss_severity`: CVE severity level
- `affected_list`: List of affected products with version information

## Outputs

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE_Check.CVE_ID | String | The CVE identifier |
| CVE_Check.Result.Hostname | String | Firewall hostname |
| CVE_Check.Result.IPAddress | String | Firewall IP address |
| CVE_Check.Result.SWVersion | String | PAN-OS software version |
| CVE_Check.Result.IsFirewallVersionAffected | Boolean | Whether PAN-OS version is affected by the CVE |
| CVE_Check.Result.GlobalProtectVersion | String | GlobalProtect client version |
| CVE_Check.Result.IsGlobalProtectVersionAffected | Boolean | Whether GlobalProtect version is affected by the CVE |
| CVE_Check.Severity | String | CVE severity level |

## Context Example

```json
{
    "CVE_Check":{
        "CVE_ID": "CVE-2072-1234", 
        "Result": [
            {
                "Hostname": "fw-affected",
                "IPAddress": "1.1.1.1", 
                "SWVersion": "10.2.3",
                "IsFirewallVersionAffected": true, 
                "GlobalProtectVersion": "6.0.1",                                    
                "IsGlobalProtectVersionAffected": true                                    
            }, 
            {
                "Hostname": "fw-patched",
                "IPAddress": "2.2.2.2", 
                "SWVersion": "10.2.3-h2",
                "IsFirewallVersionAffected": false, 
                "GlobalProtectVersion": "6.0.3",                                    
                "IsGlobalProtectVersionAffected": false 
            }], 
        "Severity": "MEDIUM"
    }
}
```

#### Human Readable Output

## CVE-2072-1234

| Hostname | IPAddress | SWVersion | IsFirewallVersionAffected | GlobalProtectVersion | IsGlobalProtectVersionAffected |
|----------|-----------|-----------|---------------------------|----------------------|--------------------------------|
| fw-affected | 1.1.1.1 | 10.2.3 | True | 6.0.1 | True |
| fw-patched | 2.2.2.2 | 10.2.3-2 | False | 6.0.3 | False |

## Notes

- The script implements the CVE schema algorithm from <https://cveproject.github.io/cve-schema/schema/docs>.
- Hotfix versions require exact matches for status changes.
- If a CVE doesn't apply to the PAN-OS software version or the GlobalProtect client package version, the output will specify the affected status on these 2 versions. For any other installed package versions, please inspect the CVE details.
