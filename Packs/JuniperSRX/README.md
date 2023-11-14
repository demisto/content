# Juniper SRX
This pack includes Cortex XSIAM content.

## Configuration on Server Side
You need to configure your Juniper SRX device to forward Syslog messages.

Perform the following in order to configure log forwarding:
1. Log in to the Juniper SRX device CLI console.
2. Run the below command:
```bash
set system syslog host <IP address of the remote Syslog server> any any
```
The instructions above set the logging with default configuration values.


Note: In order to parse the timestamp correctly, make sure that the SRX devices are configured with the default time zone (UTC).
The supported time formats are: 
- yyyy-MM-ddThh:mm:%E3S (2021-12-08T10:00:00.665)
- MMM dd hh:mm:ss (Nov 10 10:00:00)

More information can be found [here](https://supportportal.juniper.net/s/article/SRX-Getting-Started-Configure-System-Logging?language=en_US) and [here](https://supportportal.juniper.net/s/article/SRX-Getting-Started-Configure-Logging?language=en_US).


## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as vendor<- juniper
   - product as product<- srx
 