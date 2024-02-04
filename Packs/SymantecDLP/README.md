Symantec Data Loss Prevention (DLP) provides comprehensive discovery, monitoring, and protection capabilities that gives
you total visibility and control over your confidential data. It enables detecting and preventing data breaches, theft, 
or unauthorized removal or movement of your sensitive corporate data. 
It provides both content inspection and contextual analysis of data sent via messaging applications such as email and instant messaging.


## What does this pack do?

- Discover where your data incident originated from, i.e., endpoint or network.
- Scan local hard drives to gain deep visibility into sensitive files that users are storing on their laptops and desktops.
- View incident details in the default layout, such as Incident Type, Severity, Detection Server Name, Group Name, Policy Violation, etc.
- Protect data from being exposed or stolen in real-time.
- Monitor user activity to ensure that they do not send sensitive or critical information outside the corporate network. 


<~XSIAM>
# Symantec Data Loss Prevention
This pack includes Cortex XSIAM content.

## Configuration on Server Side
DLP supports two methods for generating Syslog events: "Syslog Response Rule" notifications and "Syslog Server Alerts".

### Configure a Log to a Syslog Server action
In order to send logs via syslog, you will need to create a response rule with a "Log to a Syslog Server" action.
1. In the Enforce Console, navigate to **Manage** &rarr; **Policies** &rarr; **Response Rules**.
2. Click on **Add Response Rule**.
3. Leave the type of response rule as **Automated Response** and click **Next**.
4. Enter the below:
    - **Rule Name** - "Cortex XSIAM Syslog" 
    - **Description** - "This response rule sends is configured to send logs via syslog, to the Cortex XSIAM Broker VM.".
5. Select **Log to a Syslog Server** from the Actions dropdown list and click **Add Action**.
6. Enter the Host name or IP Address of the syslog server under **Host**.
7. Edit the Port for the syslog server, if necessary.
8. Select a communication protocol.
   You can select UDP or TCP.
   If you select TCP, you can secure communications to the syslog server by selecting Enable TLS Client Authentication.
9. Copy and paste the below configuration under **Message**:
    ```bash
   "APPLICATION_NAME":"$APPLICATION_NAME$", "APPLICATION_USER":"$APPLICATION_USER$", "ATTACHMENT_FILENAME":"$ATTACHMENT_FILENAME$", "BLOCKED":"$BLOCKED$", "DATAOWNER_NAME":"$DATAOWNER_NAME$", "DATAOWNER_EMAIL":"$DATAOWNER_EMAIL$", "DESTINATION_IP":"$DESTINATION_IP$", "ENDPOINT_DEVICE_ID":"$ENDPOINT_DEVICE_ID$", "ENPOINT_LOCATION":"$ENDPOINT_LOCATION$", "ENDPOINT_MACHINE":"$ENDPOINT_MACHINE$", "ENDPOINT_USERNAME":"$ENDPOINT_USERNAME$", "PATH":"$PATH$", "PARENT_PATH":"$PARENT_PATH$", "INCIDENT_ID":"$INCIDENT_ID$", "MACHINE_IP":"$MACHINE_IP$", "MATCH_COUNT":"$MATCH_COUNT$", "OCCURRED_ON":"$OCCURRED_ON$", "POLICY":"$POLICY$", "RULES":"$RULES$", "PROTOCOL":"$PROTOCOL$", "REPORTED_ON":"$REPORTED_ON$", "SCAN":"$SCAN$", "SENDER":"$SENDER$", "MONITOR_NAME":"$MONITOR_NAME$", "SEVERITY":"$SEVERITY$", "STATUS":"$STATUS$", "SUBJECT":"$SUBJECT$", "TARGET":"$TARGET$", "USER_JUSTIFICATION":"$USER_JUSTIFICATION$", "URL":"$URL$", "RECIPIENTS":"$RECIPIENTS$", "INCIDENT_SNAPSHOT":"$INCIDENT_SNAPSHOT$"
   ```
   This will format the log's message in a json format.
10. Select the **Informational** Level from the **Level** dropdown list.
11. Click **Save**.
    
### Assign a response rule to a policy
After creating the response rule with the "Log to a Syslog Server" action, you will have to assign it to a policy in order for it to apply.
1. In the Enforce Console, navigate to **Manage** &rarr; **Policies** &rarr; **Policy List**.
2. Select the policy you want to collect logs from using syslog.
3. Go to the **Response** tab, and select the **Cortex XSIAM Syslog** rule you have created in the previous section.
4. Click **Add Response Rule** to add the response rule to the policy.
5. Click **Save**
6. Repeat steps 2-5 for any additional policies you want to collect logs from and send to Cortex XSIAM via syslog.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4.  When configuring the Syslog Collector, set the following parameters:
    | Parameter     | Value    
    | :---          | :---                    
    | `Protocol`    | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in step 8 under "Configure a Log to a Syslog Server action")  
    | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Symantec DLP.
    | `Vendor`      | Enter ****. 
    | `Product`     | Enter ****. 

</~XSIAM>