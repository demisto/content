# Cisco Stealthwatch
This pack includes Cortex XSIAM content. 

Today, companies have large networks with lots of devices stretching further than ever.
Finding the latest threat is like looking for a needle in a haystack. Stealwatch (or in its new name "Secure Network Analytics") analyzes your company's billions of network sessions, and provides analytics for your query flows and security events to enable you to determine when something looks suspicious and respond to any network threats.
​
## What does this pack do
​
- Lists security events and returns the results to the context.
- Runs queries on Cisco Stealthwatch flows and returns its results to the context.
- Maps logs to "One Data Model".



## Configuration on Server Side
You need to configure Cisco Stealthwatch to forward Syslog messages in custom LEEF format.

### Configure Custom syslog format
1. Log in to the Stealthwatch Management Console (SMC).
2. Go to **Configuration** > **Response Management**.
3. Click the **Syslog Formats** tab and then click **Add New**.

| Parameter   |                   Value     |
|-------------|-----------|
| Name        |  The name for the syslog message action.   |
| Description |  A description for the syslog message.    |
| Facility  | 16 - Local Use 0 (local0).   |
| Severity  | Severity level of the logs.           |

4. In the Message box, paste the following:

`LEEF:2.0|Lancope|Stealthwatch|6.8|{alarm_type_id}|0x7C|eventName={alarm_type_name}|src={source_ip}|dst={target_ip}|dstPort={port}|proto={protocol}|msg={alarm_type_description}|fullmessage={details}|start={start_active_time}|end={end_active_time}|cat={alarm_category_name}|alarmID={alarm_id}|sourceHG={source_host_group_names}|targetHG={target_host_group_names}|sourceHostSnapshot={source_url}|targetHostSnapshot={target_url}|flowCollectorName={device_name}|flowCollectorIP={device_ip}|domain={domain_name}|exporterName={exporter_hostname}|exporterIPAddress ={exporter_ip}|exporterInfo={exporter_label}|targetUser={target_username}|targetHostname={target_hostname}|sourceUser={source_username}|alarmStatus={alarm_status}|alarmSev={alarm_severity_name}`

### Configure syslog message action
1. Log in to the Stealthwatch Management Console (SMC).
2. Go to **Configuration > Response Management**.
3. Click the **Actions** tab and then click **Add** > **Syslog Message**.
4. Configure the following parameters in the opened window:

| Parameter   |                      Value                      |
|-------------|-----------------------------------------------|
| Name        |     The name for the syslog message action.     |
| Description |      A description for the syslog message.      |
| Enabled     |       Default value is set to "enabled".        |
| IP Address  |        The IP address of the Broker VM.         |
| Port        |          The default port is port 514.          |
| Format      | Select the custom syslog format you configured. |

5. Click **Test Action** and if everything is good, click **Save**.

### Configure Rule
1. Log in to the Stealthwatch Management Console (SMC).
2. Go to **Configuration** > **Response Management**.
3. Click the **Rules** tab and then click **Add New Rule**.
4. Click **Host Alarm**.
5. Fill in a rule name in the **Name** field and a description in the **Description** field.
6. Create rules and specify the different conditions for them to be triggered. For the Host Alarm, combine as many possible types in a statement as possible, in order to cover all the triggered alarms.
7. In the **Associated Actions** section, enable the syslog action message you configured (for both active and inactive).

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

**Note**: The name of the dataset will be assigned automatically as "lancope_stealthwatch_raw".
