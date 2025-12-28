<~XSIAM>

## Overview
Cisco Adaptive Security Appliances (ASA) is a unified security solution that integrates firewall capabilities, intrusion prevention (IPS), and VPN services. It safeguards network environments by managing traffic flow, blocking threats, and providing secure connectivity for remote users.

## This pack includes:

Data normalization capabilities: 
  * Rules for parsing and modeling Cisco ASA logs that are ingested via the BrokerVM on Cortex XSIAM. 
    * The ingested Cisco ASA logs can be queried in XQL Search using the *`cisco_asa_raw`* dataset.

***

## Data Collection

### Cisco ASA side

1. To enable logging, enter the below command:

    `logging enable` - Enables the transmission of syslog messages to all output locations.


2. To configure Cisco ASA to send logging information to a Syslog Server, enter the below command:

    `logging host interface_name ip_address [tcp[/port] | udp[/port]] [format emblem]`

For more information about syslog configuration see the official [Cisco ASA docs](https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/63884-config-asa-00.html#toc-hId-68106104).

### Cortex XSIAM side - Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow the below steps to configure the Broker VM to receive Cisco ASA logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

    | Parameter    | Value                                                                                                                       |
    |:-------------|:----------------------------------------------------------------------------------------------------------------------------|                  
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Cisco ASA). | 
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Cisco ASA.   |
    | `Vendor`     | Enter Cisco                                                                                                                 |
    | `Product`    | Enter ASA

</~XSIAM>