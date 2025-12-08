
# Huawei Firewall

## Overview

The Huawei USG6000E series are AI-powered firewalls built for businesses.  
They use smart threat detection to actively stop advanced threats and include a special hardware accelerator to boost performance for content security detection and IP security services.

<~XSIAM>

## This Pack Includes

### Data Normalization and Querying Capabilities

- Data modeling rules to normalize Huawei firewall logs that are ingested via Broker VM to Cortex XSIAM.
- Querying ingested logs in XQL Search using the **`huawei_fw_raw`** dataset.

## Supported Log Categories

#### Traffic management

|Module Name  |Details  |
|:--|:--|
|BWM  |Bandwidth module  |  

#### System management

|Module Name  |Details  |
|:--|:--|
|PAF  |Customization of a product adapter file (PAF)  |
|SSH  |STelnet module  |
|SYSTEM  |CPU, memory, session usage alarm  |
|TFTP  |TFTP module  |
|UPDATE  |Signature database update  |
|VOSCPU  |CPU usage  |
|VOSMEM  |Memory usage  |
|FWLCNS  |License module  |
|SNMPMAC  |Across-Layer-3 MAC Identification  |

### Supported timestamp formats

|Format  |Example  |
|:--|:--|
|MMM dd yyyy HH:mm:ss  |Aug 17 2024 12:30:50|

***

## Enable Data Collection

### Configure Huawei Firewall

1. Enable the Information Center. For instructions, see the [Huawei documentation](https://support.huawei.com/hedex/hdx.do?docid=EDOC1100092598&id=EN-US_TASK_0178943611).
2. Navigate to **System**.
3. In the left pane, select **Log Configuration**.
4. Select the **Log Configuration** tab and configure the following settings:

    **System Logs**
    - Enter the **_Log Host IP Address_**.
    - Enter the **_Port_** number (default is 514).

    **Service Logs**
    - For **_Log Format_**, select **Syslog**.

For more details on configuring log output, see the [Huawei documentation](https://support.huawei.com/hedex/hdx.do?docid=EDOC1100092598&id=EN-US_XTASK_0178928516).

### Cortex XSIAM - Broker VM Configuration

To create or configure the Broker VM, see the [Cortex XSIAM documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow these steps to configure the Broker VM to ingest Huawei firewall logs.  

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. In the **APPS** column on the **Brokers** tab, add the **Syslog** app for the relevant broker instance.
3. If the **Syslog** app already exists, hover over it and click **Configure**.
4. Click **Add New**.
5. Configure the Syslog Collector with the following parameters:

   | Parameter     | Value
   | :---          | :---
   | `Protocol`    | Select the protocol (UDP, TCP, or Secure TCP) that you configured on your Huawei firewall.
   | `Port`        | Enter the syslog port for the Broker VM to listen on. This must match the port configured on the Huawei firewall (default: 514).
   | `Vendor`      | Enter **Huawei**.
   | `Product`     | Enter **FW**.

Note:  

- By default, the timestamp in the log header is in UTC.  
- To set the system time via the web UI, see the [Huawei documentation](https://support.huawei.com/hedex/hdx.do?docid=EDOC1100092598&id=EN-US_XTASK_0178938248).

</~XSIAM>
