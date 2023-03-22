# Cisco Firepower
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure Cisco Firepower to forward logs in CEF format via the System Event Streamer (eStreamer).

To collect logs from Cisco Firepower to XSIAM in CEF format, use the information described  [here](https://www.cisco.com/c/en/us/td/docs/security/firepower/710/api/estreamer/EventStreamerIntegrationGuide.html) to configure the eStreamer service.

For more information on the event types sent via the eStreamer, use the information described [here](https://www.cisco.com/c/en/us/td/docs/security/firepower/660/configuration/guide/fpmc-config-guide-v66/analyze_events_using_external_tools.html#ID-2219-00000439).

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.


1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - cisco
   - product as product - firepower



**What does the XSOAR integration does?**

Use the Cisco Firepower integration for unified management of firewalls, application control, intrusion prevention, URL filtering, and advanced malware protection.

*Supported Actions:*
- List zones, ports, and URL categories.
- List security group tags, use security group tags, vlan tags, vlan tags groups, and applications.
- List, create, and update policy assignments.
- Get, create, update, and delete network objects.
- Get, create, update, and delete network group objects.
- Get, create, update, and delete host objects.
- Get, create, update, and delete access policies.
- Get, create, update, and delete access rules.
- Get deployable devices, device records, and task statuses.
- Deploy to devices.



This pack contains:
- An integration with Cisco Firepower.
- A playbook for appending network objects in Cisco Firepower.
- An XSIAM modeling rules.