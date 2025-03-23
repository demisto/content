# Integration:
The Cisco Security Management Appliance (SMA) is used to centralize services from Email Security Appliances (ESAs).

## What does this pack do?
- Retrieve spam quarantined messages.
- Release and delete messages from spam quarantine.
- Retrieve, add, append, edit, or delete a list entry - blocklist and safelist of spam quarantine. 
- Centralized tracking messages.
- Retrieve tracking messages enrichment summaries - AMP, DLP, URL.
- Centralized Reporting - get Cisco SMA's statistics reports.
- Fetch quarantine messages as incidents.

# Syslog Collection
Follow the below step to collect Cisco SMA logs via syslog.

Data normalization capabilities: 
  * Rules for parsing and modeling on Cortex XSIAM. 
  * The ingested Cisco SMA logs can be queried in XQL Search using the *`Cisco_SMA_raw`* dataset.

## Configuration on Server Side
Please follow the steps described [here](https://www.cisco.com/c/en/us/td/docs/security/security_management/sma/sma14-0/b_sma_admin_guide_14_0/b_NGSMA_Admin_Guide_chapter_01100.html#con_1062565)

*Note:
The logs will receive the correct timezone only when the UTC timezone is set.*


This pack contains an integration, whose main purpose is to centralize services from Cisco Email Security Appliances (ESAs) in Cisco Security Management Appliance services.

## Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as  ->  Cisco
   - product as -> SMA
