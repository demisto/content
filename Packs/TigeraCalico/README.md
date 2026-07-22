# Tigera Calico

<~XSIAM>

## Overview

Tigera Calico Open Source is a networking and security solution for containers, virtual machines, and native host-based workloads. It supports a broad range of platforms including Kubernetes, OpenShift, Docker EE, OpenStack, and bare metal services.
Whether you opt to use Calico's eBPF data plane, Linux's standard networking pipeline, or the Windows data plane, Calico delivers blazing-fast performance with true cloud-native scalability. Calico provides developers and cluster operators with a consistent experience and set of capabilities whether running in public cloud or on-premises, or on a single node or across a multi-thousand node cluster.

## What does this pack do?

Provides data normalization capabilities:
• Rules for parsing and modeling Tigera Calico Secure logs that are ingested via the Broker VM into Cortex XSIAM
• The ingested Tigera Calico Secure logs can be queried in XQL Search using the tigera_calico_raw dataset

## Supported log categories

Mapping of Tigera Calico Events, Audit and Traffic.

### Supported timestamp formats

Timestamp parsing is based on `start_time` second epoch timestamp.
***

## Data collection

Perform the following steps on the Tigera Calico side and then the Cortex XSIAM side to set up the collection of data using the content pack's modeling and parsing rules.

### Tigera Calico side

1. Update the LogCollector resource named tigera-secure to include a Syslog section with your syslog information.
    You can update the syslog information be done during installation by editing the custom-resources.yaml by applying it or after installation by editing the resource with the command:
    'kubectl edit logcollector tigera-secure'
    Example:
        apiVersion: operator.tigera.io/v1
        kind: LogCollector
        metadata:
        name: tigera-secure
        spec:
        additionalStores:
            syslog:
            (Required) Syslog endpoint, in the format: protocol://host:port
            endpoint: tcp://1.2.3.4:514
            (Optional) If messages are being truncated set this field
            packetSize: 1024
            (Required) Types of logs to forward to syslog. Specify at least one type.
            logTypes:
            - Audit
            - DNS
            - Flows
            - IDSEvents
2. Set which types of Calico Cloud log data to send to syslog. The syslog section contains a field called `logTypes`, which allows you to list the log types to include. Permitted log types: Audit, DNS, Flows, IDSEvents
3. Enable TLS for syslog forwarding by including the `encryption` option in the `syslog` section.
    Example:
    apiVersion: operator.tigera.io/v1
    kind: LogCollector
    metadata:
    name: tigera-secure
    spec:
    additionalStores:
        syslog:
        (Required) Syslog endpoint in the format: protocol://host:port
        endpoint: tcp://1.2.3.4:514
        (Optional) If messages are being truncated, set this field
        packetSize: 1024
        (Optional) To Configure TLS mode
        encryption: TLS
        (Required) Types of logs to forward to syslog. Specify at least one option.
        logTypes:
        - Audit
        - DNS
        - Flows
        - IDSEvents
4. Using the self-signed CA with the field name `tls.crt`, create a `configmap` in the `tigera-operator` namespace named `syslog-ca`.
    Example:
    'kubectl create configmap syslog-ca --from-file=tls.crt -n tigera-operator'
For more information [Link to the official docs](https://docs.tigera.io/calico-cloud/observability/elastic/archive-storage).

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).
Follow these steps to configure the Broker VM to receive Tigera Calico logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. In the **APPS** column under the **Brokers** tab, add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`   | Select **UDP** for default forwarding, **TCP** or **Secure TCP** (depending on the protocol you configured in Tigera Calico).                   |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Tigera Calico.                   |
    | `Format`     | Enter *Format*.                                                                                                                                 |
    | `Vendor`     | Enter Tigera.                                                                                                                                   |
    | `Product`    | Enter Calico.                                                                                                                                   |

</~XSIAM>
