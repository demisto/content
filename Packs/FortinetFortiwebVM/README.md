# Fortinet Fortiweb Pack
Fortinet Fortiweb enables you to manage WAF policies, block cookies, URLs, hostnames.

---

## What does this pack do?

### Fortiweb Cloud

- XDM Mapping for Attack, Audit and Traffic logs in CEF format.
- Timestamp ingestion for Attack, Audit and Traffic logs.

### Fortiweb VM

- XDM Mapping for Attack and Traffic logs in CEF format.
- Timestamp ingestion for Attack and Traffic logs.
- Create, update, delete, or retrieve protected hostnames, groups, and members.
- Create, update, delete, or retrieve IP lists groups and members.
- Create, update, delete, or retrieve Geo IP groups and members.
- Create, update, delete, or retrieve server policies.
- Create, update, delete, or retrieve whitelist members.
- Retrieve information and status of the systems.

This pack contains an integration, whose main purpose is to perform controlled changes on hosted web applications.

---

## Collect Events from Vendor
In order to receive logs, use the [Broker VM](#broker-vm) option. <br>
For Traffic logs via Fortiweb Cloud, you are required to send the logs with [Amazon S3](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3) services.
<br>

### Fortiweb Cloud

**_Audit_ Logs**
* [How to export Audit logs to a log server](https://docs.fortinet.com/document/fortiweb-cloud/23.3.0/user-guide/367276/audit-logs).
1. Go to **Global** &rarr; **System Settings** &rarr; **Settings**.
2. Enable **Audit Logs Export**.
3. Configure the following mandatory settings: <br>

| Field Name | Value |
| :---------------- | :------: |
| Server Type | Syslog |
| IP/Domain and Port | IP & Port |
| Protocol | TCP |
| Log Format | CEF |

4. Click **Save**. 
<br>

**_Attack_ Logs**
* [How to export Attack and Traffic logs to a log server](https://docs.fortinet.com/document/fortiweb-cloud/23.3.0/user-guide/681595/log-settings).
1. Go to **Log Settings**.
2. Enable **Attack Log Export**.
3. Click **Add Log Server**.
4. Configure the following mandatory settings: <br>

| Field Name | Value |
| :---------------- | :------: |
| Server Type | Syslog |
| IP/Domain and Port | IP & Port |
| Protocol | TCP |
| Log Format | CEF |

5. Click **OK**. 
<br>

**_Traffic_ Logs (AWS S3)**
* [How to export Attack and Traffic logs to a log server](https://docs.fortinet.com/document/fortiweb-cloud/23.3.0/user-guide/681595/log-settings).
1. Go to **Log Settings**.
2. Enable **Traffic Log Export**.
3. Configure the following mandatory settings: <br>

| Field Name | Value |
| :---------------- | :------: |
| Server Type | AWS S3 |
| Bucket Name | Enter the AWS S3 bucket name. |
| Region | Enter the region code, for example, ap-southeast-1. |
| Access Key ID	| Enter the access key ID of the S3 bucket. |
| Secret Key ID	| Enter the secret key ID of the S3 bucket. |
| Prefix / Folder | Enter the prefix / folder to store the traffic log. |

4. Click **Save**.

---
<br>

### Fortiweb VM

* [How to export Attack, Traffic and Event logs to a log server](https://docs.fortinet.com/document/fortiweb/7.6.0/administration-guide/303842/logging).

**Enable Logging**
1.  First, configure a SIEM Policy. Before you can log the resource, you enable logging for the log type that you want to use as a trigger.
2.  **Log&Report** &rarr; **Log Config** &rarr; **Other Log Settings**.
3.  Make sure that the Attack, Traffic and Event logs checkboxes are marked.
4.  Click **Apply**.

**Configure a SIEM Policy**
1.  Before you can log to the resource, you enable logging for the log type that you want to use as a trigger.
2.  Go to **Log&Report** &rarr; **Log Policy** &rarr; **SIEM Policy**.
3.  For **Policy Name**, enter a unique name that other parts of the configuration can reference.
4.  Click **Create New**, set the **Policy Type** to **ArcSight CEF**.
5.  Input an IP address and port for the server.
6.  Click **OK**.

**Configure Log Settings**
1. Go to **Log&Report** &rarr; **Log Config** &rarr; **Global Log Settings**.
2. Configure and enable a **SIEM** setting option: <br>

| Field Name | Value |
| :---------------- | :------: |
| Log Level | Select the severity level that a log message must equal or exceed in order to be recorded to this storage location. |
| SIEM Policy | Select the policy to use when storing log messages remotely. |

3. Click **Apply**.


