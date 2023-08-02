# Tanium Threat Response
This pack includes Cortex XSIAM content.


## Configuration on Server Side

### Tanium Threat Response logs
In order to forward Tanium threat response logs, follow the below steps.

You will need to configure a Socket Receiver on Tanium side. 

1. Go to **Modules** > **Connect**.
2. Enter a name and description for the connection.
3. From the **Source** dropdown, select **Event**.
4. From the **Event Group** dropdown, select **Tanium Threat Response** or **Tanium Detect**.
5. Select **Match Alerts Raw**.
6. From the **Destination** dropdown, select **Socket Receiver**.
7. Specify a unique name for the **Destination Name**.
8. Under **Host**, fill in the name or the IP address of the SIEM.
9. Specify the port number under **Port**.
10. Select **JSON** from the dropdown under **Format**.
11. Click the **Listen for this Event** checkbox.
12. Click **Save**.

More information can be found [here](https://docs.tanium.com/threat_response/threat_response/overview.html#Integrat)

**Note:**
Make sure to send the logs in UTC time. 
Don't modify the value type of the "Timestamp" field. This field is set to UTC by default.

### Tanium Integrity Monitor logs
In order to forward Tanium integrity monitor logs, follow the below steps.

You will need to configure a Socket Receiver on Tanium side.

1. Go to **Modules** > **Interact**.
2. Copy the below question to the "Ask a Question" box under **Explore Data** and run it.
```bash
Get Computer Name and Last Logged In User and Integrity Monitor - Monitor Events[10,0,360,15,0,""] from all machines
```
3. Click **Save** and configure the question as described in the next steps.
4. Under **Name**, write "XSIAM Integrity Montior".
5. From the **Content Set** dropdown, select **Base**.
6. Verify that the text under **Question Text** matches the question mentioned on step 2.
7. Check the "Reissue this question every" check box, and set it to 2 hours.
8. Go to **Modules** > **Connect**.
9. Enter a name and description for the connection.
10. From the **Source** dropdown, select **Saved Question**.
11. From the **Saved Question Name** dropdown, select **XSIAM Integrity Montior**.
12. From the **Destination** dropdown, select **Socket Receiver**.
13. Specify a unique name for the **Destination Name**.
14. Under **Host**, fill in the name or the IP address of the SIEM.
15. Specify the port number under **Port**.
16. Select **JSON** from the dropdown under **Format**.
17. Click **Save**.

More information can be found [here](https://docs.tanium.com/integrity_monitor/integrity_monitor/overview.html?cloud=false)

**Note:**
Make sure to send the logs in UTC time. 
Don't modify the value type of the "Event Time" field. This field is set to UTC by default.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

#### Tanium Threat Response logs
1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - tanium
   - product as product - threat_response

#### Tanium Integrity Monitor logs
1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - tanium
   - product as product - integrity_monitor