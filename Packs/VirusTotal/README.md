Note: Support for this pack moved to the partner on Oct 1, 2021. Please contact the partner directly via the support link on the right.

VirusTotal inspects submitted hashes, URLs, domains, and IP addresses for suspicious behavior.

## What does this pack do?
This pack includes 3 integrations:
- VirusTotal (API v3) integration:
   - Analyze suspicious hashes, URLs, domains, and IP addresses.
   - Use your premium API key for advanced indicator analysis (Check "Premium Subscription' box in the integration parameters)

- VirusTotal Premium (API v3) integration:
   - Fetch live hunt notifications as incidents.
   - Use retro hunt to analyze files with custom YARA rules.
   - Download suspicious files from VirusTotal for further analysis.
   - Group several files from VirusTotal into a password-protected ZIP file.
   - Get a PCAP file generated from VirusTotal's sandbox for further analysis.

- VirusTotal:
   - Analyze suspicious hashes, URLs, domains, and IP addresses.

This pack also includes 4 playbooks:
- **Create Zip from VirusTotal**: Create a zip file from specified hashes that exist in VirusTotal.
- **Detonate File - VirusTotal**: Detonate one or more files using the VirusTotal integration. This playbook returns relevant reports to the War Room and file reputations to the context data.
- **Detonate File - VirusTotal (API v3)**: Detonate one or more files using the VirusTotal (API v3) integration. This playbook returns relevant reports to the War Room and file reputations to the context data.
- **Detonate URL - VirusTotal (API v3)**: Detonate one or more urls using the VirusTotal integration. This playbook returns relevant reports to the War Room and file reputations to the context data.
