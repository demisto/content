# Juniper SRX

<~XSIAM>

## Configuration on Server Side

You need to configure your Juniper SRX device to forward Syslog messages.

Perform the following in order to configure log forwarding:

1. Log in to the Juniper SRX device CLI console.
2. Run the following commands:

```
set security log mode stream
set security log format sd-syslog
set security log source-address 10.204.225.164
```

Note: In order to parse the timestamp correctly, make sure that the SRX devices are configured with the default time zone (UTC).
The supported time formats are:

- yyyy-MM-ddThh:mm:%E3S (2021-12-08T10:00:00.665)
- MMM dd hh:mm:ss (Nov 10 10:00:00)
- yyyy-MM-ddThh:mm:%E3S%Ez (2025-01-01T12:00:00.000-05:00) #Offset

More information can be found [here](https://www.juniper.net/documentation/us/en/software/nce/nce-srx-cluster-management-best/topics/task/chassis-cluster-srx-log-message-configuring.html#id-configuring-srx-series-branch-devices-to-send-traffic-log-messages-through-the-data-plane).

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
   </~XSIAM>
