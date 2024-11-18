<~XSIAM>
# F5 APM
This pack includes Cortex XSIAM content.

## Configuration on Server Side
Follow the below workflow to configure F5 APM to forward logs in Syslog format.

### Creating a pool of remote logging servers
Create a pool of remote log servers which will include the IP address of the Broker VM.
1. Navigate to **Local Traffic** > **Pools**.
2. Click **Create**.
3. In the **Name** field, type "XSIAM".
4. Using the **New Members** setting, add the IP address for the Broker VMs that you want to include in the pool:
   - Type an IP address in the **Address field**, or select a node address from the Node List.
   - Type a service number in the Service Port field, or select a service name from the list.
   - Click **Add**.
5. Click **Finished**.

### Creating a remote high-speed log destination
Create a log destination of the **Remote High-Speed Log** type to specify that log messages are sent to a pool of remote log servers.
1. Navigate to **System** > **Logs** > **Configuration** > **Log Destinations**.
2. Click **Create**.
3. In the **Name** field, type "XSIAM".
4. From the **Type** list, select **Remote High-Speed Log**.
5. From the **Pool Name** list, select the pool of remote log servers that you created in the previous step, called "XSIAM".
6. From the Protocol list, select the protocol used by the high-speed logging pool members.
7. Click **Finished**.

### Creating a formatted remote high-speed log destination
Create a formatted logging destination to specify that log messages are sent to a pool of remote log servers.
1. Navigate to **System** > **Logs** > **Configuration** > **Log Destinations**.
2. Click **Create**.
3. In the **Name** field, type "XSIAM".
4. From the **Type** list, select **Remote Syslog**.
5. From the **Syslog Format** list, select a format for the logs.
6. From the **High-Speed Log Destination** list, select the destination that you created in the previous step.
7. Click **Finished**.

### Creating a publisher
Create a publisher to specify where the BIG-IP system sends log messages for specific resources.
1. Navigate to **System** > **Logs** > **Configuration** > **Log Publishers**.
2. Click **Create**.
3. In the **Name** field, type "XSIAM".
4. For the **Destinations** setting, select a destination from the **Available list**, and click `**<<**` to move the destination to the Selected list.
5. Click **Finished**. 

### Configuring log settings for access system and URL request events
Create log settings to enable event logging for access system events or URL filtering events or both.
1. Navigate to **Access** > **Overview** > **Event Logs** > **Settings**.
2. Click **Create** for a new APM log setting.
3. In the **Name** field, type "XSIAM".
4. Select both of the following options:
   - Enable access system logs
   - Enable URL request logs
5. To configure settings for access system logging, select **Access System Logs** from the left pane.
6. For access system logging, from the **Log Publisher** list, select the log publisher you created in the previous step.
7. Make sure that the log level for the access system logging is left as **Notice** (default).
8. To configure settings for URL request logging, select **URl Request Logs** from the left pane.
9. For URL request logging, from the **Log Publisher** list, select the log publisher you created in the previous step.
10. Select all of the following options:
   - Log Allowed Events
   - Log Blocked Events
   - Log Confirmed Events
11. Assign the log setting you have created to the access profiles you want their logs to be sent to Cortex XSIAM.
    - Select **Access Profiles** from the left pane.
    - Move access profiles between the **Available** and the **Selected** lists.
12. Click **OK**.

### Configuring remote syslog entries to use ISO timestamp format
* Formal documentation for ISO timestamp configuration [doc](https://my.f5.com/manage/s/article/K02733223).
1. Log in to **tmsh** by typing the following command:
```bash 
   tmsh
```
2. To define the desired **syslog** filter that references the remote server, type the following command:
```bash 
   edit /sys syslog all-properties
```
3. Within the **include** statement, insert the following lines:
```bash 
   options { proto-template(t_isostamp); };
      template t_isostamp { template(\"$ISODATE $HOST $MSGHDR$MSG\\n\"); };
      
      destination d_remote_loghost {
            tcp(\"10.10.10.1\" port(514) template(t_isostamp));
         };
```
4. Exit the text editor by pressing Esc to leave Insert mode and then type the following key sequence:
```bash 
   :wq!
```
5. At the following prompt, type **y** to save the changes to the file.
6. Save the configuration by typing the following command:
```bash 
   save /sys config
```

**Pay Attention**: 
Timestamp ingestion is only supported for the suggested ISO timestamp format to implement for F5 APM logs- ***YYYY-MM-DDThh:mm:ssTZ***.

For more information, refer to F5 BIG-IP APM formal [docs](https://techdocs.f5.com/en-us/bigip-17-0-0/big-ip-access-policy-manager-third-party-integration/logging-and-reporting.html#GUID-3A9514E3-33CC-43AB-840F-17624F4CA180).

Note:
Consider [suppressing sending SSL access and request messages to remote syslog servers](https://my.f5.com/manage/s/article/K16932).

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**. 
2. Go to the apps tab and add the **Syslog** app. If it already exists, click the **Syslog** app and then click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following values:
   - vendor as f5 
   - product as apm
</~XSIAM>