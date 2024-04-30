# Illusive Networks
This pack includes XSIAM content.

#### Incident Response
Provide SOC teams with automated collection and analysis of Illusive incidents and the option to extend Illusive data and forensics analysis to other potentially malicious activities discovered on your network.

* Automatically collect data and forensics from new incidents detected by Illusive
* Enrich SOC data by retrieving a rich set of incident and forensics information, including: 1) host details and forensics from a potentially compromised host, 2) a forensics timeline, 3) forensics analysis, 4) additional data
* Auto-analyze collected data and calculate incident severity to speed up SOC response times
* Collect forensics from any compromised host and retrieve a forensics timeline

#### Deceptions and Attack Surface Manager
Manage the Illusive’s deceptive entities and deception policies to control the way Illusive deploys deceptions across the network, and gain insight into your network’s topography.
* Retrieve detailed lists of approved and suggested deceptive servers and users
* Approve, delete, and query deceptive entities
* Manage deception policy assignments per host
* Retrieve attack surface insights for Crown Jewels and specific hosts

<~XSIAM>
### Collect Events from Vendor

In order to use the collector, you can use the following option to collect events from the vendor:
 - [Broker VM](#broker-vm)

You will need to configure the vendor and product for this specific collector.

#### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - `illusive` as vendor
   - `illusive` as product
</~XSIAM>
