<~XSIAM>

## Overview

Cisco Identity Services Engine (ISE) is a next-generation NAC solution used to manage endpoint, user, and device access to network resources within a zero-trust architecture.

## This pack includes

Data normalization capabilities:

* Rules for parsing and modeling Cisco ISE logs that are ingested via Syslog on Cortex XSIAM.
  * The ingested Cisco ISE logs can be queried in XQL Search using the *`cisco_ise_raw`* dataset.

### Supported Timestamp Formats

* MMM dd hh:mm:ss
* yyyy-MM-dd hh:mm:ss.nnn [+|-]nn:nn
* yyyy-MM-dd hh:mm:ss.nnn [+|-]nnnn

***

## Data Collection

### Cisco ISE side

To configure basic Syslog collection, do the following:

1. Go to **Administration** > **System** > **Logging** > **Remote Logging Targets**
2. Click **Add** and then fill the required details.
3. Click **Save**, and then verify the creation of the new target by going to the **Remote Logging Targets** page.

**Note:**
To prevent log segmentation, set the Maximum Length of the log to **8096**.

For more information on remote logging configuration, see [here](https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/222223-configure-external-syslog-server-on-ise.html).

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, see [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM).

Do the following to configure the Broker VM to ingest Cisco ISE logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Under the **Brokers** tab go to the **APPS** column and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. Set the Syslog Collector parameters:

    | Parameter    | Value                                                                                                                       |
    |:-------------|:----------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Cisco ISE). |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Cisco ISE.   |
    | `Vendor`     | Enter cisco.                                                                                                                |
    | `Product`    | Enter ise.                                                                                                                  |

</~XSIAM>
