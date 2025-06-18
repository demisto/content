This playbook executes hygiene check commands using the PAN-OS integration and identifies items configured in a manner that do not meet minimum security best practices.  It looks for the following:
1. Log Forwarding Profiles
    1. Profiles without Enhanced Logging enabled
    2. Profiles with no match list (rules) configured
    3. Profiles that do not include rules to forward Traffic or Threat logs
2. Security Zones with no Log Forwarding Profile assigned
3. Spyware Profiles that do not:
    1. Block signatures of Critical and High severity
    2. Alert on (or block) signatures of Medium and Low severity
4. URL Filtering Profiles do not block the default URL categories blocked in the pre-defined profile
5. Vulnerability Profiles that do not:
    1. Block signatures of Critical and High severity
    2. Alert on (or block) signatures of Medium and Low severity
6. Security Rules that do not:
    1. Log at Session End
    2. Have a Log Forwarding Profile assigned
    3. Have Security Profiles assigned for Anti Virus, Spyware, Vulnerability, and URL Filtering (or a group that includes each).

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Panorama

### Scripts

This playbook does not use any scripts.

### Commands

* pan-os-hygiene-check-log-forwarding
* pan-os-hygiene-check-security-rules
* pan-os-hygiene-check-security-zones
* pan-os-hygiene-check-spyware-profiles
* pan-os-hygiene-check-url-filtering-profiles
* pan-os-hygiene-check-vulnerability-profiles

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| target_device | The serial number of a specific firewall to target \(Used when connected to Panorama\) \[Optional\] |  | Optional |
| integration_instance_name | The name of the configured Integration Instance to run commands with. \[Optional\] |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PANOS.ConfigurationHygiene.Result | A list of hygiene check results \(constructed as dictionaries\) including a description of the issue found, the configuration location \(container name\), and the name of the object affected by the issue. | unknown |
| PANOS.ConfigurationHygiene.Summary | A list of hygiene check summaries \(constructed as dictionaries\) describing the overall result of hygiene checks and how many issues of each type were found, if any. | unknown |

## Playbook Image

---

![PAN-OS - Run Security Configuration Hygiene Checks](../doc_files/PAN-OS_-_Run_Security_Configuration_Hygiene_Checks.png)
