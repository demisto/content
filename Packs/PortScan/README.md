Port scanning is a reconnaissance method often used by attackers when gathering information about weak points in networks they want to penetrate, or when looking for valuable targets within an already compromised network. By running port scans, hackers are able to identify running services and potential vulnerabilities that can be used to gain control over systems and eventually pivot and gain control over the organization’s network. Misconfigurations in the network may also create port scan alerts.

This pack helps you speed response by providing the necessary configuration and checks for correctly responding to port scans originating outside or within the network, and takes appropriate steps to quickly contain malicious events.


##### What does this pack do?
- Gathers information about IPs and enriches hostnames associated with the port scan.
- Identifies critical assets involved in the incident, and escalates the incident accordingly.
- Identifies malware associated with internal network scans, hunts instances of the malware across the organization and blocks it.
- Pivots from attacking IPs to find hosted domains and block them to prevent further malicious activity from the same source.
- Blocks ports upon approval and isolates infected hosts.


As part of this pack, you will also get out-of-the-box incident fields, layouts and playbooks for port scan investigations. All of these are easily customizable to suit the needs of your organization.

_For more information, visit our [Cortex XSOAR Developer Docs](https://xsoar.pan.dev/docs/reference/playbooks/port-scan---generic)_

![Port_Scan_Generic](doc_files/Port_Scan_-_Generic.png)
