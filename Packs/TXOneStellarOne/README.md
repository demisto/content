<~XSIAM>

## Overview

TXOne StellarOne is a centralized management console for TXOne's OT (Operational Technology) endpoint security agents (StellarProtect and StellarProtect Legacy Mode). It provides threat detection, application lockdown, and device control for industrial environments, and forwards audit, system, console, and agent security events in Syslog CEF format.

## This pack includes

Data normalization capabilities:

* Rules for parsing and modeling TXOne StellarOne audit, system, console, and agent (StellarProtect) logs that are ingested via the Broker VM into Cortex XSIAM.
  * The ingested TXOne StellarOne logs can be queried in XQL Search using the *`txone_stellarone_raw`* dataset.

## Supported log categories

| Category      | Category Display Name |
|:--------------|:----------------------|
| Agent Event   | Agent Event           |
| Console Log   | Console Log           |
| AUDIT_EVENT   | Audit Event           |
| SYSTEM_EVENT  | System Event          |

### Supported timestamp formats

* Epoch milliseconds (13-digit), e.g. `1765893322000`.
* `%b %d %Y %H:%M:%S GMT%Ez`, e.g. `Jan 01 2026 20:00:28 GMT+00:00`.

***

## Data Collection

### TXOne StellarOne side

Configure StellarOne to forward events to a Syslog server (the Cortex XSIAM Broker VM):

1. Log in to the StellarOne management console.
2. Navigate to **Administration** → **Configuration** → **Syslog**.
3. Enable **Send logs to a syslog server**.
4. Set the **Server address** to the Broker VM IP address, the **Port**, and the **Protocol** (UDP/TCP/TLS).
5. Set the format to **CEF**.
6. Select the event types to forward (audit, system, console, and agent events).
7. Save the configuration.

For more information, contact TXOne StellarOne customer support for proper guidance on configuring Syslog forwarding.

### Cortex XSIAM side - Broker VM

For instructions on how to create or configure the Broker VM, see [Set up and configure Broker VM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow the instructions below to configure the Broker VM to receive TXOne StellarOne logs:

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

    | Parameter    | Value                                                                                                                                |
    |:-------------|:-------------------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in TXOne StellarOne).   |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from TXOne StellarOne.     |
    | `Format`     | Enter **CEF**.                                                                                                                       |
    | `Vendor`     | Select **Auto-Detect**.                                                                                                               |
    | `Product`    | Select **Auto-Detect**.                                                                                                              |

</~XSIAM>
