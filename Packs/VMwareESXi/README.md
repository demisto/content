<~XSIAM>

## Overview

VMware ESXi is a hypervisor that enables you to run multiple virtual machines on a single server. This integration collects logs related to user logins, VM operations, and system updates, providing enhanced visibility into your virtualized environment.

## This pack includes

### Data normalization capabilities

* Rules for VMware ESXi logs ingested via the Broker VM into Cortex XSIAM.

### Supported timestamp formats

* Pay attention: Timestamp parsing is available for UTC timezone in the following formats:
  * `%Y-%m-%dT%H:%M:%SZ` - UTC +00:00 format.  
  * `%Y-%m-%dT%H:%M:%E*SZ` - UTC +00:00 format with fractional seconds.
  * `%Y-%m-%dT%H:%M:%E*S` - UTC +00:00 format with fractional seconds.

***

## Data Collection

### VMware ESXi side

To forward ESXi logs to the collector, you must configure the syslog target and allow the traffic through the ESXi firewall.

#### Configuration via vSphere Client (UI)

**1. Configure the Log Target**

1. Log in to the vSphere Client.
2. Select the ESXi host in the inventory hierarchy.
3. Navigate to **Configure** > **System** > **Advanced System Settings**.
4. Click **Edit**.
5. Search for `Syslog.global.loghost`.
6. Enter the collector address in the following format:
   * **UDP:** `udp://<Collector_IP>:514`
   * **TCP:** `tcp://<Collector_IP>:514`
7. Click **OK**.

**2. Allow Traffic (Firewall)**

1. With the host still selected, navigate to **Configure** > **System** > **Firewall**.
2. Click **Edit**.
3. Scroll down and locate the `syslog` rule.
4. Check the box to **Enable** the rule.
5. Click **OK**.

For more information, see [here](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-monitoring-and-performance-8-0/monitoring-events-and-alarms/remote-streaming-of-events.html).

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow the below steps to configure the Broker VM to receive VMware ESXi logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

| Parameter    | Value                                                                                                                         |
|:-------------|:------------------------------------------------------------------------------------------------------------------------------|
| `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in VMware ESXi). |
| `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from VMware ESXi.   |
| `Format`     | Enter **Raw**.                                                                                                                |
| `Vendor`     | Enter **vmware**.                                                                                                             |
| `Product`    | Enter **esxi**.                                                                                                               |

</~XSIAM>
