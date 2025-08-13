<~XSIAM>
 
## Overview
Calico Open Source is a networking and security solution for containers, virtual machines, and native host-based workloads. It supports a broad range of platforms including Kubernetes, OpenShift, Docker EE, OpenStack, and bare metal services.

Whether you opt to use Calico’s eBPF data plane, Linux’s standard networking pipeline, or the Windows data plane, Calico delivers blazing-fast performance with true cloud-native scalability. Calico provides developers and cluster operators with a consistent experience and set of capabilities whether running in public cloud or on-premises, or on a single node or across a multi-thousand node cluster.
 
## This pack includes:
 
Data normalization capabilities:
• Rules for parsing and modeling Tigera Calico Secure logs that are ingested via the Broker VM into Cortex XSIAM
• The ingested Tigera Calico Secure logs can be queried in XQL Search using the tigera_calico_raw dataset  
 
## Supported log categories
Mapping of Tigera Calico Events, Audit, Traffic
 
### Supported timestamp formats:
Timestamp parsing is available for the MMM dd HH:MM:SS format.
 
***
 
## Data Collection
 
### Tigera Calico side
1.  Update the LogCollector resource named tigera-secure to include a Syslog section with your syslog information.
    This can be done during installation by editing the custom-resources.yaml by applying it or after installation by editing the resource with the command:
    'kubectl edit logcollector tigera-secure'
    Example:
        apiVersion: operator.tigera.io/v1
        kind: LogCollector
        metadata:
        name: tigera-secure
        spec:
        additionalStores:
            syslog:
            # (Required) Syslog endpoint, in the format protocol://host:port
            endpoint: tcp://1.2.3.4:514
            # (Optional) If messages are being truncated set this field
            packetSize: 1024
            # (Required) Types of logs to forward to Syslog (must specify at least one option)
            logTypes:
            - Audit
            - DNS
            - Flows
            - IDSEvents

2.  control which types of Calico Cloud log data you would like to send to syslog. The Syslog section contains a field called logTypes which allows you to list which log types you would like to include. The allowable log types are: Audit, DNS, Flows, IDSEvents        
3.  TLS configuration - enable TLS option for syslog forwarding by including the "encryption" option in the Syslog section.
    Example:
    apiVersion: operator.tigera.io/v1
    kind: LogCollector
    metadata:
    name: tigera-secure
    spec:
    additionalStores:
        syslog:
        # (Required) Syslog endpoint, in the format protocol://host:port
        endpoint: tcp://1.2.3.4:514
        # (Optional) If messages are being truncated set this field
        packetSize: 1024
        # (Optional) To Configure TLS mode
        encryption: TLS
        # (Required) Types of logs to forward to Syslog (must specify at least one option)
        logTypes:
        - Audit
        - DNS
        - Flows
        - IDSEvents
4.  Using the self-signed CA with the field name tls.crt, create a configmap in the tigera-operator namespace named, syslog-ca. 
    Example:
    'kubectl create configmap syslog-ca --from-file=tls.crt -n tigera-operator'

For more information <[Link to the official docs](https://docs.tigera.io/calico-cloud/observability/elastic/archive-storage)>.
 
### Cortex XSIAM side - Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).
 
Follow the below steps to configure the Broker VM to receive Tigera Calico logs.
 
1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:
 
    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|                 
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Tigera Calico).                 |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Tigera Calico.                   |
    | `Format`     | Enter Format.             
|
    | `Vendor`     | Enter Tigera.                                                                                                                                   |
    | `Product`    | Enter Calico.                                                                                                                                   |
    
</~XSIAM>