## [Unreleased]


## [20.4.1] - 2020-04-29
#### New Playbook
Investigates a port scan incident. The incident may originate from outside or within the network. The playbook:
- Enriches the hostname and IP address of the attacking endpoint
- Escalates the incident in case a critical asset is involved
- Hunts malware associated with the alerts across the organization
- Blocks detected malware associated with the incident
- Blocks IP addresses associated with the malware, if a malicious file was involved
- Pivots from the attacking IP to detect and block malicious domains hosted on the IP (for external scan)
- Isolates the attacking endpoint (for internal scan)
- Allows manual blocking of ports through an email communication task

If you're using one or more of the following products, make sure to configure their corresponding playbook inputs, respectively:
Splunk - "Splunk Indicator Hunting"
QRadar - "QRadar Indicator Hunting v2"
Palo Alto Networks Cortex Data Lake/Panorma/Autofocus/Analytics - "PANW - Hunting and threat detection by indicator type V2"