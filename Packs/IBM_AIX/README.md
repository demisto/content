# IBM AIX
This pack includes Cortex XSIAM content. 

## Configuration on Server Side
You need to configure your IBM AIX instance to forward audit event messages with syslog.

Open your IBM AIX instance, and follow these instructions (Product Documentation)[https://www.ibm.com/docs/en/dsm?topic=asdo-configuring-your-aix-server-device-send-syslog-events-qradar]: 
1. Log in to your IBM AIX appliance as a *root* user.
2. Open the */etc/syslog.conf* file.
3. To forward the system authentication logs to QRadar, add the following line to the file:
```bash
    auth.info @SyslogServer_IP_address
```
4. Save and exit the file.
5. Restart the syslog service:
```bash
    refresh -s syslogd
```

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - ibm
   - product as product - aix
