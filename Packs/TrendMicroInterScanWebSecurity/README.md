# Trend Micro InterScan Web Security Suite (IWSS)

<~XSIAM>
This pack includes Cortex XSIAM content.

## Configuration on Server Side

This section describes the configuration that needs to be done on the Trend Micro InterScan console in order to forward the IWSS event logs to Cortex XSIAM Broker VM via syslog.

1. Log in to your Trend Micro InterScan console.
2. Navigate to **Logs** &rarr; **Syslog Configuration** from the main menu.
3. Click **Add** under Syslog Server.
4. Select the **Enable Syslog** checkbox.
5. Enter the IP address of the target [Cortex XSIAM Syslog Broker VM](#broker-vm).
6. Enter the syslog service port that the target Cortex XSIAM Broker VM is listening on for receiving forwarded events from Trend Micro IWSS.
7. Select the log type(s) or priority of the logs that should be sent to Cortex XSIAM.
8. Click **Save**.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
3. When configuring the Syslog Collector, set the following parameters:

   | Parameter     | Value
   | :---          | :---
   | `Protocol`    | Select **UDP**.
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Trend Micro IWSS.
   | `Vendor`      | Enter **TrendMicro**.
   | `Product`     | Enter **IWSS**.

</~XSIAM>
