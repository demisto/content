Use the Palo Alto Networks Threat PCAP Extract playbook to automatically export PCAP from firewalls using either direct integration or via Panorama.  HTTP Push notification is performed from the firewall or LC directly to XSOAR to ckick off the process.
Included sample JSON payload for HTTP notification template as well as converted sample to use to map the fields to the incident type.

## What does this pack do?
- Download PCAP from PAN-OS based on HTTP Push notification, optionally parse with PCAPMinerv2 to extract flows.


The content pack contains 1 playbooks 
-  NetOps - ThreatPCAPExtract