# Forcepoint DLP
This pack includes Cortex XSIAM content.


## Configuration on Server Side
Use the Settings > General > Remediation page in the Data Security module of the Forcepoint Security Manager to define the location of the syslog server and mail release gateway used for remediation.

1. Under Syslog Settings, enter the IP address or hostname of the syslog server, and the logging port.
2. To set the origin of syslog messages, select Use syslog facility for these messages, then use the drop-down menu to select the type of message to appear in the syslog:
   * **User-level Messages (#1)** logs generic user-level messages, such as "username/password expired".
   * **Security/Authorization Messages (#4)** logs authentication and authorization-related commands, such as "authentication failed for admin user".
   * **Security/Authorization Messages (#10)** logs non-system authorization messages inside a protected file (for information of a sensitive nature, such as passwords).
   * **Local use 0-7 (#16-23)** specifies unreserved facilities available for any local use. Processes and daemons that have not been explicitly assigned a facility can use any of the "local use" facilities. Configuration is done in the syslog.conf file.
   To send incident data to the syslog, select **Audit Incident** > **Send Syslog Message** in the action plan for the policy.
3. Click **Test Connection** to send the syslog server a verification test message.
4. Under Release Quarantined Emails, specify which gateway to use when releasing a quarantined email message.
   * The default is **Use the gateway that detected the incident**. This gateway could be Forcepoint Email Security or the protector MTA, depending on your subscription.
   * To define a specific gateway, select **Use the following gateway**, then enter the gateway IP address or hostname and port.
5. If only recipients of a message should be able to release it from quarantine, select **Validate user before releasing message**.
The system then ensures that the person attempting to release a message is a recipient of the message, and therefore authorized. Unauthorized users receive an email notification that they are not allowed release the message.
6. Click **OK** to save your changes.

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.


### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**.
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, change the format to *CEF*.

*NOTE*: The log format is CEF. The name of the *Vender* and the *Product* will be based on the vendor and product fields in the raw data.
