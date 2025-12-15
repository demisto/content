<~XSIAM>

## Overview

The Riverbed Flow Gateway content pack helps you truly understand your network by collecting and centralizing NetFlow data from all your devices.
It gathers flow information from standard routers and switches, along with Riverbed's own AppResponse and SteelHead devices. This gives you a complete, end-to-end view of your network's traffic.
All the collected flow data is deduplicated for accuracy and then sent to NetProfiler for in-depth analysis and reporting. This enables you to get precise insights, optimize your network monitoring investments, and reduce overall costs.

## This pack includes

Data normalization capabilities:

* Rules for parsing and modeling network logs that are ingested via Broker VM into Cortex XSIAM.
* The ingested Riverbed Flow Gateway logs can be queried in XQL Search using the *`riverbed_flow_gateways_raw`* dataset.

### Supported timestamp format

* The syslog is in **RFC 5424 format**, and the parsing rule supports UTC timezone. For example: *`1985-04-12T23:20:50.52Z`*.

***

## Data collection

### Riverbed Flow Gateways side

To send syslog data from Riverbed to a remote server:

1. At the realm level, select the **Logging** tab.
2. Under **Remote Logging**, click **On**.
3. Click **Add Remote Log Server**.
4. Select the protocol to transfer the log to the syslog server: UDP (default), TCP, or TLS (Transport Layer Security version 2.12).
    * If you select TLS as the transport method, you must copy a certificate for the remote log server into the remote log server certificate field.
5. Click **Enable**.
6. Specify the remote syslog server’s **IPv4 address** or **hostname**. The remote server must be running the standard syslogd utility.
7. Enter the syslog server **port number** for sending syslog messages.
8. Select the minimum severity level for the log messages to control the amount of messages logged. By default, SteelConnect logs all syslog messages with a priority level of Info and above.
9. Click **Submit**.

For more information, see [here](https://support.riverbed.com/bin/support/static/k5tvfpu9msjd2u0gje8l0l5a4s/html/aed70h9b6j6mo2v8vmocsg88jh/sc_ug_html/index.html#page/scm/Group1/remote_syslog.html).

### Cortex XSIAM side

#### Broker VM

To create or configure the Broker VM, see [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

To configure the Broker VM to receive Riverbed Flow Gateways logs:

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

    | Parameter    | Value                                                                                                                                    |
    |:-------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Riverbed Flow Gateways). |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Riverbed Flow Gateway.    |
    | `Format`     | Enter **syslog**.                                                                                                                        |
    | `Vendor`     | Enter **riverbed**.                                                                                                                      |
    | `Product`    | Enter **flow_gateways**.                                                                                                                 |

</~XSIAM>
