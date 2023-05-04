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

This pack contains an integration, whose main purpose is to centralize services from Cisco Email Security Appliances (ESAs) in Cisco Security Management Appliance services.

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as vendor <-  Cisco
   - product as product <- SMA
