# Mcafee Web Gateway
This pack includes Cortex XSIAM content.

Skyhigh Secure Web Gateway (SWG) is a cloud-native web security solution that provides an advanced layered protection from threats and data loss with integrated RBI, CASB, and DLP capabilities in the web and cloud. It enables organizations to implement a simplified SSE architecture that delivers security, scalability, and availability for a distributed and remote workforce.

<~XSIAM>

## Configuration on Server Side
You need to configure Web Gateway to forward Syslog messages.
 
### Add a rule for sending access log data
1. Select **Policy** &rarr; **Rule Sets**.
2. Click **Log Handler**, expand the **Default** rule set, and select the nested Access Log rule set.
3. Add the following rule to make access log data available to the daemon that sends it to the syslog server.
    | Criteria      | Action                | Event
    | :---          | :---                  |:--- 
    | Always        | Continue              | Syslog (6, UserDefined.logLine)
4. Click **Save Changes**.

## Adapt the rsyslog.conf system file for sending access log data
1. Select **Configuration** &rarr; **File Editor**.
2. On the files tree, select **rsyslog.conf**.
3. Edit the file to adapt it for sending access log data.
   1. Look for the following line:
    ``` text
   *.info;mail.none;authpriv.none;cron.none /var/log/messages
   ```
   2. Replace **mail** with **daemon** in this line and insert a **-** (dash) before the path information.
    ``` text
   *.info;daemon.none;authpriv.none;cron.none -/var/log/messages
   ```
   This modification prevents the syslog daemon from sending data to the var/log/messages partition on the disk of the Web
Gateway appliance system.
   3. You can now direct the data to the intended destination:
      * To send data to a syslog server under TCP, insert - `daemon.info @<IP>:<Port>`
      * To send data to a syslog server under the UDP protocol, insert - `daemon.info @<IP>:514`


*  Pay Attention: Timestamp ingestion is currently available for the **time_stamp** field in **%d/%h/%Y %H:%M:%S %z** (e.g. 11/Oct/2023:04:50:18 -0500) format.


## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option. 
 
### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
You can configure the specific vendor and product for this instance.
 
1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **Apps** column under the **Brokers** tab and add the **Syslog Collector** app for the relevant broker instance. If the app already exists, hover over it and click **Configure**.
3. Click **Add New** for adding a new syslog data source.
4. When configuring the new syslog data source, set the following values:
   | Parameter     | Value   
   | :---          | :---        
   | `Vendor`      | Enter **mcafee**.
   | `Product`     | Enter **webgateway**.
</~XSIAM>

<~XSOAR>
This Skyhigh Secure Web Gateway content pack contains the **Skyhigh Secure Web Gateway** integration that manages block and allow lists within Skyhigh SWG.

## What does this pack do?
Manages the block and allow lists within Skyhigh SWG.
</~XSOAR>