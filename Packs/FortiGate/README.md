<~XSIAM>
# Fortigate
This pack includes Cortex XSIAM content.

Fortigate versions: 7.x

## Configuration on Server Side
You need to configure Fortigate to forward Syslog messages.

1. Log in to the FortiGate web interface using your admin credentials.
2. Open a CLI console by clicking the **_>** icon in the top right corner
4. Run the following command:
```bash 
   config log syslogd setting
    set status enable
    set server <syslog_IP>
    set format cef
    set mode udp
    set port <port_number>
```

More information can be found [here](https://docs.fortinet.com/document/fortigate/7.4.1/administration-guide/250999/log-settings-and-targets)
## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

* Support for timestamp parsing is available only for the **FTNTFGTeventtime** field in UTC +0000 time zone.

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as Fortinet
   - product as FortiGate
</~XSIAM>

    
 