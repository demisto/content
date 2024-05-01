
# BeyondTrust Privileged Remote Access
<~XSIAM>
This pack includes Cortex XSIAM content.


## Configuration on Server Side
This section describes the configuration that needs to be done on a BeyondTrust B Series Appliance in order to forward its event logs to Cortex XSIAM Broker VM via syslog.

Follow the steps below:
1. Access your BeyondTrust/appliance administrative interface. 
2. Go to /**appliance** &rarr; **Security** &rarr; **Appliance Administration**, and scroll down to the **Syslog** section.
3. Set a new syslog server configuration entry with the following values:              
    - `Remote Syslog Server` - Enter the IP address of the target [Cortex XSIAM Syslog Broker VM](#broker-vm). 
    - `Message Format` - Select **RFC 5424 compliant** for the default forwarding configuration over UDP, or **Syslog over TLS(RFC 5425)**  for an encrypted syslog connection over TLS (see [Set Syslog over TLS](https://www.beyondtrust.com/docs/privileged-remote-access/getting-started/deployment/cloud/syslog-over-tls.htm) for additional details). 
    -  `Port` - Enter the syslog service port that the target Cortex XSIAM Broker VM is listening on for receiving forwarded events from BeyondTrust appliances. 

See BeyondTrust [Syslog Message Reference Guide](https://www.beyondtrust.com/docs/privileged-remote-access/how-to/integrations/syslog/index.htm) for additional details.


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
   | `Protocol`    | Select **UDP** for the default forwarding, or **Secure TCP** if the syslog forwarding on the BeyondTrust appliance was defined with the **Syslog over TLS(RFC 5425)** message format.  
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from BeyondTrust appliances. 
   | `Vendor`      | Enter **BeyondTrust**. 
   | `Product`     | Enter **PRA**. 

## Remarks
As described on the BeyondTrust [syslog message format](https://www.beyondtrust.com/docs/privileged-remote-access/how-to/integrations/syslog/message-format.htm) & [syslog message segmentation](https://www.beyondtrust.com/docs/privileged-remote-access/how-to/integrations/syslog/message-segmentation.htm) docs, syslog messages that are larger than 1KB are segmented by the BeyondTrust syslog service into multiple separate individual syslog messages. 

The modeling rules provided in this pack are applied to each event individually, so on such cases where a syslog message is divided into multiple events, each event would be mapped individually as a standalone event.
   
</~XSIAM>
 