
# McAfee NSM (Network Security Manager)
This pack includes Cortex XSIAM content.

## McAfee NSM Syslog configuration
*McAfee NSM syslog event types:*
* IPS Events
* Faults
* User Activity (audit logs)

*config Syslog IPS Events:*
1. on McAfee NSM go to Manager -> Setup -> Notification -> IPS Events -> syslog.
2. click *YES* on "Enable Syslog Notification".
3. bellow click on *+* and add Target server. 
   * if you not configured target server alick add neer the "Target Server" and  fill the target server details.
   ![link](https://raw.githubusercontent.com/demisto/content/2063d324e6515a85b484705df5e4d153425e5110/Packs/McAfeeNSM/doc_imgs/nsm_add_target_server.png)
4. on Facility select "Log Alert (note 1)".
5. Severity mapping - not touch, need to be:
   ![link](https://raw.githubusercontent.com/demisto/content/2063d324e6515a85b484705df5e4d153425e5110/Packs/McAfeeNSM/doc_imgs/nsm_ips_severity_mapping.png)
6. click on the Checkbox to enable "Notify for all Alerts" and click save.

*config Syslog Faults Events:*
1. on McAfee NSM go to Manager -> Setup -> Notification -> Faults -> syslog.
2. click *YES* on "Enable Syslog Notification".
3. fill the fields "Server Name or IP Address" and "Port".
4. on *facilities* dropdown select "Security/authorization (code 4)".
5. severity mapping not touch, will be like:
    ![link](https://raw.githubusercontent.com/demisto/content/53399299a79f6d8323502c6489c02b87a8720a7b/Packs/McAfeeNSM/doc_imgs/nsm_faults_severity_mapping.png)
6. on *Forward Faults* dropdown select "informational and above".
7. on *Message Preference* click on the checkbox "Syslog default" and click save.

*config Syslog User Activity (audit logs) Events:*
1. on McAfee NSM go to Manager -> Setup -> Notification -> User Activity -> syslog.
2. click *YES* on "Enable Syslog Notification".
3. fill *Server Name or IP Address* and *port*.  
4. select Protocol on *Protocol* dropdown.
5. on *Facilities* dropdown select "Log Alert (note 1)".
6. on severity mapping not touch, will be like:
    ![link](https://raw.githubusercontent.com/demisto/content/53399299a79f6d8323502c6489c02b87a8720a7b/Packs/McAfeeNSM/doc_imgs/nsm_audit_severity_mapping.png)
7. on *Forward audit* dropdown select "Allow All Auditlogs".
7. on *Message Preference* click on the checkbox "Syslog default" and click save.

## Event Time configuration

By Default on Fault and IPS events (syslog) not have event time, to add event time do the followin steps:
*IPS Events*
1. on McAfee NSM go to Manager -> Setup -> Notification -> IPS Events -> syslog.
2. choose target server and click on the pencil (edit)
3. on message part add in the end of the string " at  $IV_ATTACK_TIME$"
4. click save

*Syslog Faults*
1. on McAfee NSM go to Manager -> Setup -> Notification -> Faults -> syslog.
2. on message preference click edit and add to the end of the message " at  $IV_FAULT_TIME$"
3. click save

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as vendor - mcafee
   - product as product - nsm
 