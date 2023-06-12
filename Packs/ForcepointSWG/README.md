
# Forcepoint Secure Web Gateway
This pack includes Cortex XSIAM content.


## Configuration on Server Side
In the **Settings** > **General** > **SIEM Integration** page you can configure Websense software to send log data from the Filtering Service to a supported Security Information and Event Management (SIEM) solution.
Before enabling the SIEM integration, make sure an instance of Websense Multiplexer is installed for each Policy Server in your deployment.

Perform these steps for each Policy Server instance in your deployment:
1. Select **Enable SIEM integration for this Policy Server** to turn on the SIEM integration feature.
2. Provide the IP address of the BrokerVM, as well as the communication Port to use for sending the data.
3. Specify the Transport protocol (UDP or TCP) to use when sending data to XSIAM.
4. Select **syslog/CEF** format to use. This determines the syntax of the string used to pass log data to the integration.
5. Click **OK** to cache your changes. Changes are not implemented until you click **Save and Deploy**.

When you save your changes, Websense Multiplexer connects to the Filtering Service and takes over the job of distributing log data to both the Log Server and the selected SIEM integration.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Click the **Apps** tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following value:
   - Format as "Auto-Detect".

 