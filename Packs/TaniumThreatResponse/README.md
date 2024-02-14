# Tanium Threat Response
This pack includes Cortex XSIAM content.

<~XSIAM>
## Configuration on Server Side
You need to configure a Socket Receiver on the Tanium side. 

Perform the following steps to configure the Socket Receiver:
1. Go to **Modules** > **Connect**.
2. Enter a name and description for the connection.
3. From the **Source** dropdown, select **Event**.
4. From the **Event Group** dropdown, select **Tanium Threat Response** or **Tanium Detect**..
5. Select **Match Alerts Raw**.
6. From the **Destination** dropdown, select **Socket Receiver**.
7. Specify a unique name for the **Destination Name**.
8. Under **Host**, fill in the name or the IP address of the SIEM.
9. Specify the port number under **Port**.
10. elect **JSON** from the dropdown under **Format**.
11. Click the **Listen for this Event** checkbox.
12. Click **Save**.

More information can be found [here](https://docs.tanium.com/threat_response/threat_response/overview.html#Integrat)

**Note:**
Make sure to send the log in UTC time. 
Don't modify the value type of the **Timestamp** field. This field is set to UTC by default.
The supported time format is yyyy-MM-ddThh:mm:ss.nnnZ (2022-01-01T10:00:00.000Z).

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - tanium
   - product as product - threat_response
</~XSIAM>