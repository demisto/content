Guardicore delivers easy-to-use Zero Trust network segmentation to security practitioners
across the globe. Our mission is to minimize the effects of high-impact breaches, like
ransomware, while protecting the critical assets at the heart of your network. We shut
down adversarial lateral movement, fast. From bare metal to virtual machines and containers,
Guardicore has you covered across your endpoints, data centers and the cloud.
Our software-based platform helps you become more secure to enable your organization’s digital transformation.

- East West Segmentation / Micro Segmentation capabilities to reduce your attack surface and remove unnecessary streams of communication between servers and applications.
- Improve operational efficiency and agility by eliminating downtime during server or application migrations.
- Enforce Zero Trust security protocols with ease and simplify your organization's path to compliance.

- [Guardicore Website](https://www.guardicore.com/)
- [Guardicore Centra Demo Request](https://www.guardicore.com/lp/demo-request/)
- [Short video on Mastering Segmentation](https://www.youtube.com/watch?v=unUmrOFEKIU)

<~XSIAM>

## Overview

Akamai GuardiCore is a micro-segmentation platform designed to secure hybrid cloud and data center infrastructure. It enforces Zero Trust principles by isolating workloads at a granular level, preventing lateral movement and containing potential breaches. The solution combines deep visibility into application dependencies with deception technology, enabling organizations to detect threats and ensure security across dynamic environments.

## This pack includes

### Data normalization capabilities

- Rules for parsing and modeling Akamai GuradiCore logs that are ingested via the Broker VM into Cortex XSIAM.
- The ingested Akamai GuardiCore logs can be queried in XQL Search using the *`akamai_guardicore_raw`* dataset.

### Supported log categories

| Category       | Category Display Name |
|:---------------|:----------------------|
| System         | System Event          |
| Audit          | Audit Record          |
| Agent          | Agent Log Event       |
| Label          | Label Record          |
| Network        | Network Log Event     |
| Incidents      | Incident Record       |

### Supported timestamp formats

Timestamp parsing support assumes a UTC +0000 format is being used.
***

## Data Collection

### Akamai GuardiCore side

Configuring syslog export enables you to export wide range of data, please choose this one.

1. From Administration, select **Data Export** -> **Syslog**.
2. Click the **Create syslog Integration** button.
3. In the **Create New Syslog Integration** section, select **Events Syslog Exporter**, and configure the fields below:

| Field           | Description                                                                 |
|:----------------|:----------------------------------------------------------------------------|
| Name            | Enter a **name** for the Syslog integration                                 |
| Type            | Select **Events Syslog Exporter**                                           |
| Syslog Host     | Enter the **IP address** of the Broker VM                                   |
| Syslog Port     | Enter **514**                                                               |
| Syslog Protocol | Select **UDP**                                                              |
| Verify Host     | **Enable** this option (should be always checked as advised by the vendor). |

4. In the **Exporting Options** section, configure the following:

| Field                | Description             |
|:---------------------|:------------------------|
| Display Hostname     | Enter a **name**        |
| Message Format       | Select **CEF**          |
| Format log timestamp | **Enable** this option. |

Ensure the following options are enabled for export:

- Incidents
- System alerts
- Agent logs
- Audit logs
- label changes logs
- Insight alerts

**Note:** Ensure that you allow traffic from Akamai GuardiCore source IP addresses to the Broker VM in your Firewall.

For more information, contact your akamai guardicore contact.

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow the below steps to configure the Broker VM to receive Akamai GuardiCore logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

| Parameter    | Value                                                                                                                               |
|:-------------|:------------------------------------------------------------------------------------------------------------------------------------|
| `Protocol`  | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Akamai GuardiCore). |
| `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Akamai GurdiCore.    |
| `Format`     | Enter **CEF**.                                                                                                                      |
| `Vendor`     | Enter **Akamai**.                                                                                                                   |
| `Product`    | Enter **GuardiCore**.                                                                                                               |

</~XSIAM>
