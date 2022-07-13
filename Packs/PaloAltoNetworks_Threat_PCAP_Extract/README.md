Use the Palo Alto Networks Threat PCAP Extract playbook to automatically export PCAP from firewalls using either direct integration or via Panorama.  HTTP Push notification is performed from the firewall or LC directly to XSOAR to kick off the process.
Included sample JSON payload for HTTP notification template as well as converted sample to use to map the fields to the incident type.

## What does this pack do?
- Downloads PCAP from PAN-OS devices based on HTTP POST notification to XSOAR, optionally parse with PCAPMinerv2 to extract flows.
- Can be run as a sub playbook or by itself to pull PCAPS as they are generated
- Customization can be done to add in optional integrations with Storage providers like Azure Blob or AWS S3 by inserting the intergration in the playbook in the section carved out, a flag exists to optionally perform that already integrated into the playbook.

## XSOAR Setup
- Certificate that is trusted by PAN-OS for HTTP API integration
- API Key generated for use by PAN-OS to POST incidents to XSOAR
- Ensure the integrations are installed
- Ensure the PAN-OS intergration is setup (API Key, server etc.)
- Select which method of integration (Firewall direct or via Panorama) will be used to pull PCAPs
- Ensure the playbook inputs are configured for the intergration names for PAN-OS (firewall or Panorama)
- update the Classifier and Mappers for API are set (use the sample panos-http-payload-conv.json) to import and map if manual mapping is required for fields
- Classifier will map the name field to the incident type (and layout and playbook)
- Mapper will map the fields from the payload to the fields in the incident
- Sample API_Classifier and API_mapper are include in doc_files

## PAN-OS Setup
- Determine if this will be firewalls  (many streams) or Panorama/ Log Collector sending notification to XSOAR
- HTTP Server Profile created on the firewalls or Panorama/Log Collector
- XSOAR server details created
- Create custom HTTP payload using the included sample JSON file in doc_files (panos-http-payload.json)
- Test connection from PAN-OS to XSOAR
- Attach the HTTP server profile to an existing logging profile and leverage the search for threat logs (flags has pcap)
- Commit (and Push) changes to firewalls or Log Collectors

## XSOAR Validation
- ensure that Threat logs that have PCAP flags set (down green arrow) create incidents in XSOAR

The content pack contains 1 playbooks 
-  NetOps - ThreatPCAPExtract