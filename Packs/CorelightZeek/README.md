<~XSIAM>

# Corelight Zeek

This pack includes Cortex XSIAM content.

## This pack includes

Data normalization capabilities:

* Rules for parsing and modeling network protocol logs that are ingested via the BrokerVM into Cortex XSIAM.
* The ingested Corelight Zeek logs can be queried in XQL Search using the *`corelight_zeek_raw`* dataset.

## Supported log categories

| Category | Category Display Name |
|:---------|:----------------------|
| DNS      | dns.log               |
| HTTP     | http.log              |
| NTLM     | ntlm.log              |
| Syslog   | syslog.log            |
| CONN     | conn.log              |
| Kerberos | kerberos.log          |
| DCE/RPC  | dce_rpc.log           |

### Supported timestamp format

Timestamp parsing supports a UTC +0000 format.

***

## Data Collection

### Corelight Zeek Side

You need to configure Corelight Sensor to forward Zeek Syslog messages.

1. Open the Corelight Sensor UI, and on the left menu bar click **Configuration**.
2. Open the **Export** tab and scroll down to **Export to Syslog**.
   * Under **Syslog Server**: Set your XSIAM Broker VM hostname or IP address and port.
   * Under **Transfer Protocol**: Choose **TCP**.
   * Under **Syslog Format**: Pick the *Default** (RFC5424) option.
   * Under **Syslog Facility**: Set your Syslog Facility, e.g., Local0.
   * Under **Syslog Severity**: Select the severity for the logs you will send, e.g., Info.
3. Open the **Maintain** tab.
4. Save your Syslog configuration to apply the configuration to your Corelight Zeek Sensors.

For more information, see the Corelight Zeek documentation.

## Cortex XSIAM side - Broker VM

To create or configure the Broker VM, see [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow these steps to configure the Broker VM to ingest Corelight Zeek logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

| Parameter  | Value                                                                                                                          |
|:-----------|:-------------------------------------------------------------------------------------------------------------------------------|
| `Protocol` | Select **TCP** (Corelight Zeek is not available for a UDP protocol).                                                           |
| `Port`     | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Corelight Zeek. |
| `Format`   | Enter **CORELIGHT**.                                                                                                           |
| `Vendor`     | Enter **corelight**.                                                                                                           |
| `Product`    | Enter **zeek**.                                                                                                                |

For more information, see [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-from-Corelight-Zeek)

</~XSIAM>
