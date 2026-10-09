# IBM Guardium

<~XSIAM>

This pack includes Cortex XSIAM content.

## Configuration on Server Side

To configure IBM Guardium to forward logs to Cortex XSIAM Broker VM via syslog follow the steps below.

### Creating a syslog destination for events

1. Log in to the CLI and define the IP address for Cortex XSIAM Broker VM.
2. Use SSH to log in to IBM as default user.  
Username: \<user name\>  
Password: \<password\>
3. Type the following command to configure the syslog destination for:

|  Event Type   | Command
| :---          | :---
| `informational events` | store remote add daemon.info \<IP address\>:\<port\> \<tcp\|udp\>
| `warning events` | store remote add daemon.warning \<IP address\>:\<port\> \<tcp\|udp\>
| `error events` | store remote add daemon.err \<IP address\>:\<port\> \<tcp\|udp\>
| `alert events` | store remote add daemon.alert \<IP address\>:\<port\> \<tcp\|udp\>

> **IP address** - IP address of the event collector  

> **port** - syslog port used to communicate to the event collector (default port in Guardium is 514 UDP)

> **tcp\ udp** - protocol used to communicate with the event collector

*For example:*  

``` bash
    store remote log add daemon.all <IP> udp

    store remote log add daemon.all example.com:1514 tcp
```  

[IBM Guardium - creating a syslog destination for events](https://www.ibm.com/docs/en/qsip/7.4?topic=guardium-creating-syslog-destination-events)

### Configure policies to generate syslog events

Policies in IBM Guardium are responsible for reacting to events and forwarding the event information to Cortex XSIAM Broker VM.

1. Click the **Tools tab**.
2. From the left navigation, select **Policy Builder**.
3. From the Policy Finder pane, select an existing policy and click **Edit Rules**.
4. Click **Edit this Rule individually**.
   The Access Rule Definition is displayed.
5. Click **Add Action**.
6. From the **Action** list, select one of the following alert types:
   **Alert Per Match** - A notification is provided for every policy violation.
   **Alert Daily** - A notification is provided the first time a policy violation occurs that day.
   **Alert Once Per Session** - A notification is provided per policy violation for unique session.
   **Alert Per Time Granularity** - A notification is provided per your selected time frame.
7. From the **Message Template** list, edit the message template or choose the default template (follow IBM Support link below for default template and CEF template).
8. From **Notification Type**, select **SYSLOG**.
9. Click **Add**, then click **Apply**.
10. Click **Save**.
11. Repeat this process for all rules within the policy that you want to forward to Cortex XSIAM Broker VM.

### Installing an IBM Guardium policy

1. Click the **Administration Console** tab.
2. From the left navigation, select **Configuration** &rarr; **Policy Installation**.
3. From the Policy Installer pane, select a policy that you created in the previous step.
4. From the drop-down list, select **Install and Override**.
   A confirmation is displayed to install the policy to all Inspection Engines.
5. Click **OK**.

[IBM Support - Shipping Guardium Syslog to Remote Server](https://www.ibm.com/support/pages/shipping-guardium-syslog-remote-server)

## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Set-up-and-configure-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **Apps** column under the **Brokers** tab and add the **Syslog Collector** app for the relevant broker instance. If the app already exists, hover over it and click **Configure**.
3. Click **Add New** for adding a new syslog data source.
4. When configuring the new syslog data source, set the following values:  

| Parameter     | Value
   | :---          | :---
   | `Protocol`    | TCP or UDP according to the protocol defined in the IBM Guardium CLI.
   | `Port`        | Enter the port number defined in the IBM Guardium CLI or 514 if no specific port was defined.
   | `Vendor`      | Enter **IBM**.
   | `Product`     | Enter **Guardium**.

> [!NOTE]
This content refers to IBM Guardium version 10.0

## IBM Guardium Data Security Center

The IBM Guardium Data Security Center centralizes data security, compliance, and risk management across hybrid cloud and on-premises environments. It uses Data Security Posture Management (DSPM) and specialized modules for AI security and quantum-safe cryptography to provide threat detection and regulatory reporting.

## What does this pack contain?

- API integration for the IBM Guardium Data Security Center.
- Modeling rules for activity log reports.

## API Integration

### Configure authentication and authorization in the IBM Guardium Data Security Center

1. Open the IBM Guardium Data Security Center.
2. Click **Create API key** and enter an API key description (key name).
3. Copy and securely store your API key and secret API key.

**IMPORTANT:**
The API key details are displayed only once. Ensure you copy and securely store the credentials before leaving the page.

### Configure the IBM Security Guardium integration in Cortex XSIAM

1. Go to Cortex XSIAM and navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. In the search bar, search for the **IBM Security Guardium** integration and click **Add instance**.
3. In the settings configuration pane, provide a name for your integration instance (for example,  IBM_Guardium_Integration) and paste your credentials.
4. Configure the following parameters.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of your IBM Security Guardium integration instance. Replace the default value with your specific integration instance URL. | True |
| API Key | The API key for authentication. | True |
| API Secret | The API secret for authentication. | True |
| Report ID | The ID of the report to fetch events from. | True |
| Fetch events | Whether to automatically fetch events. | False |
| Maximum number of events to fetch | The maximum number of events to fetch per run. Default is 10000. Recommended maximum is 10000. | False |
| Timestamp Field Name | The display name of the header in the report that contains the timestamp field, e.g., "Date created (local time)".<br> Note: This field name varies between different reports. | False (Required when Fetch events is enabled) |
| Trust any certificate (not secure) | Trust any certificate (not secure). | False |
| Use system proxy settings | Use system proxy settings. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ibm-guardium-get-events

***
Manual command to fetch and display events.

#### Base Command

`ibm-guardium-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command creates events; otherwise, it only displays them. Default is false. | Required |
| timestamp_field | The name of the field in the event data that contains the timestamp. <br>Note: This field name varies between different reports. If not provided, uses the value from the integration configuration. | Optional (Required when should_push_events is true) |
| limit | Maximum number of results to return. Maximum allowed is 1000. Default is 50. | Optional |
| start_time | Start time for fetching events. Supports ISO format ("2023-01-01T00:00:00") or natural language ("7 days ago", "yesterday", "1 week ago"). Defaults to 1 hour ago if not provided. | Optional |
| end_time | End time for fetching events. Supports ISO format ("2023-01-01T23:59:59") or natural language ("2 hours ago", "now"). If not provided, defaults to now. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!ibm-guardium-get-events limit=50 start_time="2024-01-01T00:00:00" end_time="2024-01-01T23:59:59" should_push_events=true```

## Additional Information

**Note:** By default, the integration fetches events from the last 12 hours on first run. This accounts for IBM Guardium event indexing delays and ensures events are captured even when indexed with significant delays.

</~XSIAM>
