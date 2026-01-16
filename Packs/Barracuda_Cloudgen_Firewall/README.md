<~XSIAM>

## Overview

Barracuda CloudGen Firewall is a next-generation firewall and SD-WAN solution. It combines security and SD-WAN into a single platform, providing secure connections across your entire network that are all managed from one central location.

## This pack includes

Data normalization and querying capabilities:

* Rules for parsing and modeling firewall activity logs that are ingested via BrokerVM into Cortex XSIAM.
  * Querying ingested Barracuda Cloudgen Firewall logs in XQL Search using the *`barracuda_cgfw_raw`* dataset.

### Supported log categories

* Logs from `box/Firewall/Activity` log file. See more information, see [here](https://campus.barracuda.com/product/cloudgenfirewall/doc/170820943/available-log-files-and-structure)
* This pack only supports syslog in a key=value format.

### Supported timestamp formats

Timestamp parsing is only supported for UNIX timestamp (UTC).

***

## Data Collection

### Barracuda Cloudgen Firewall side

You need to configure Barracuda Cloudgen Firewall to forward Syslog messages.

1. Go to **CONFIGURATION** -> **Full Configuration** -> **Box** -> **Infrastructure Services** -> **Syslog Streaming**.
2. Click **Lock**.
3. Set **Enable Syslog Streaming** to **yes**.
4. Click **Send Changes** and **Activate**.
For more information, see [here](https://campus.barracuda.com/product/cloudgenfirewall/doc/96026562/how-to-configure-syslog-streaming/)

* Important: To ensure logs are ingested and modeled correctly, you must configure the log message structure to be `key=value` pairs. Please follow the steps below:

1. Go to **CONFIGURATION** -> **Full Configuration** -> **Box** -> **Infrastructure Services**.
2. Look for  **Activity Log Mode**.
3. Change the mode to Log-Pipe-Separated-Key-Value-List. This tells the firewall to format its log entries with pipes separating the key=value pairs (e.g., key1=value1|key2=value2).
5. After changing general firewall configuration settings, perform a Firmware Restart (**CONTROL** -> **Box**) for the changes to take effect.
For more info, see [here](https://campus.barracuda.com/product/cloudgenfirewall/doc/170820177/general-firewall-configuration)

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow the below steps to configure the Broker VM to receive Barracuda Cloudgen Firewall logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

    | Parameter    | Value                                                                                                                                               |
    |:-------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Barracuda Cloudgen Firewall).       |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Barracuda Cloudgen Firewall.         |
    | `Format`     | Enter **RAW**.<br/>                                                                                                                                      |
    | `Vendor`     | Enter **barracuda**.                                                                                                                                |
    | `Product`    | Enter **cgfw**.

In order to use the collector, use the [Broker VM](#broker-vm) option.

</~XSIAM>
