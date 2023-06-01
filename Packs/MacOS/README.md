# MacOS
This pack includes Cortex XSIAM content. 
MacOS Ventura is the current supported OS for XSIAM.
<~XSIAM>
## Configuration on Server Side
You need to configure MacOS to forward Syslog messages.

Open your MacOS device and follow these step:
1. Open a Terminal on the relevant device.
2. Open the syslog config file with a vi editor, write the command **vi /etc/syslog.conf**.
3. Type **i** in order to enter editing mode.
4. Write the following like as a new line in the syslog config file- \*.\* \@"\<IP address\>"\:"\<Port\>".
5. Write **:wq** to save and exit the file.
6. Restart the syslogd daemon by writing the command **sudo launchctl stop com.apple.syslogd** and than **sudo launchctl start com.apple.syslogd**.

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - macos
   - product as product - ventura
</~XSIAM>