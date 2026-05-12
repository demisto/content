
# Radware Cloud WAF Services

<~XSIAM>  
This pack includes Cortex XSIAM content.  
It supports the following Radware Cloud Services event types:

- [Radware Cloud WAAP Service Access Logs](https://support.radware.com/app/answers/answer_view/a_id/1018351/~/cloud-waf-service-access-log-integration-guide).
  - Access logs provide detailed data regarding client access to applications protected by Cloud WAAP.
- [Radware AppWall Cloud WAF Security Event Logs](https://support.radware.com/app/answers/answer_view/a_id/1018635/~/reviewing-security-events).
  - A security event is generated whenever Cloud WAF detects an attack, when an ongoing attack
is still active, or when an ongoing attack status has changed. The generated security event
includes the information relevant to the specific attack or security breach.

See the documentation below for the configuration required for each event type to collect into Cortex XSIAM.  

## Collect Radware Cloud WAAP Service Access Logs

### AWS - S3 bucket

**On AWS**

Sign in to your AWS account and create a dedicated Amazon S3 bucket, which collects the generic logs that you want to capture.

See this [doc](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3) for further instructions on how to create a S3 bucket.

**On Radware Cloud Services**

1. Contact the Radware Support team in order to enable Access logs.
2. Navigate to **Account Settings** and fill the below attributes:
   - Bucket Name
   - Region
   - Access Key
   - Secret Key
   - Prefix (optional)
3. Click the **Advanced** tab and enable **Access log**.
4. Select the application to which to export all Access logs.

For additional information, refer to the official Radware [documentation](https://support.radware.com/).

**On XSIAM:**

1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. Click **Amazon S3**.
3. Click **Connect** or **Connect Another Instance**.
4. Set the following values:
   - SQS URL - Refer to Configure an Amazon Simple Queue Service (SQS) [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3).
   - Name as `Radware Access Log`
   - AWS Client ID
   - AWS Client Secret
   - Log Type as `Generic`
   - Log Format as `JSON`
   - Vendor as `radware`
   - Product as `access_logs`
   - Compression as `gzip`

For additional information, see this [doc](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3).

## Collect Radware AppWall Cloud WAF Security Events

In order to collect AppWall Cloud WAF Security events, you need to deploy a log-collection solution such as [Logstash](https://www.elastic.co/logstash) that can interact with [Amazon SQS](https://aws.amazon.com/sqs/), retrieve your queued event messages from Radware Cloud and forward them via Syslog to Cortex XSIAM.

Radware recommends using [Logstash](https://www.elastic.co/logstash) as the log-collection solution, however, any other third-party log-collection solution can be used as long as it has an interface with [Amazon SQS](https://aws.amazon.com/sqs/) and supports syslog forwarding.

The following steps demonstrate the configuration steps with Logstash used as the log-collection solution, under the assumption that Logstash has already been installed and deployed on your environment.

### Obtain Amazon SQS Credentials

**On Radware Cloud WAF Portal**

1. Connect to your Radware account on the Radware [Cloud WAF Portal](https://portal.cwp.radwarecloud.com/#/login).
2. Navigate to **Account** &rarr; **Account Settings**.
3. Click **Download SIEM Configuration** to download a configuration file which includes the details of the SQS event queues and your credentials for accessing them. This file has the name convention of *siemConfigFetchConfig_\<ID\>.txt*. Use this file in the next section when configuring Logstash (or any other log-collection solution you want to use).

### Configure Logstash  

The downloaded SIEM configuration file that was downloaded from Radware portal (see the previous section) already contains a predefined SQS input plugin for retrieving events from Amazon SQS.
You need to update this file to include a syslog *output* plugin that would forward the retrieved event messages to your Cortex XSIAM Broker VM via syslog.

1. Open the *siemConfigFetchConfig_\<ID\>.txt* SIEM configuration file that was downloaded from the Radware portal in the previous section.
2. Define a [Syslog output plugin](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-syslog.html) entry with the following properties:

   | Property     | Value
   | :---          | :---
   | `host`        | Enter The IP address of the Cortex XSIAM Broker VM syslog server.
   | `port`        | Enter the syslog service port number that Cortex XSIAM Broker VM should listen on for receiving Radware AppWall security events that would be forwarded from Logstash.
   | `rfc`         | Enter **rfc5424**
   | `appname`     | Enter a meaningful application name for the syslog message. For e.g., **RadwareAppWall**.

   The following example demonstrates a sample configuration with a syslog output plugin (values surrounded by angle brackets represent placeholders for dynamic values):

   ```python
   input {
      sqs {
            queue => "<WAF-Queue-ID-APPWALL_ATTACK>"
            access_key_id => "<The_WAF_Queue_Access_Key_ID>"
            region => "<queue-region>"
            secret_access_key => "<The_WAF_Queue_Secret_Access_Key>"
      }
   }
   output {
      syslog {
         host => "<THE_BROKER_VM_IP>"
         port => 514 
         rfc => "rfc5424"
         appname => "RadwareAppWall"
      }
   }
   ```

3. Save the updated configuration file in the Logstash *bin* folder, and start Logstash.

### Configure Cortex XSIAM Broker VM Syslog Server  

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **Apps** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
3. When configuring the Syslog Collector, set the following parameters:

   | Parameter     | Value
   | :---          | :---
   | `Protocol`    | Select **UDP** for the default forwarding.
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving Radware AppWall Cloud WAF security events that are forwarded from Logstash.
   | `Vendor`      | Enter **Radware**.
   | `Product`     | Enter **AppWall**.

For additional information regarding SIEM integration with Radware AppWall Cloud WAF events, refer to the [official Radware documentation](https://support.radware.com/).

</~XSIAM>
