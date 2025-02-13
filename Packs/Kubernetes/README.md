# Kubernetes
This pack includes Cortex XSIAM content. 
## Configuration on Server Side
You need to configure Kubernetes to forward Syslog messages.

The following should be configured for Kubernetes;
1. Create the audit policy file using Kubernetes [documentation](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#audit-policy)
2. Place the audit policy file in a folder that can be accessed by **kube-apiserver** pod through a volume mapping:
    `Code --> Kubectl describe pod < kube-apiserver pod > —namespace kube-system`
3. Configure the kube-apiserver to output in log mode:
    * **--audit-policy-file**
    * **--audit-log-path**

Note:
In order to parse the timestamp correctly, make sure to configure the logs to be sent in a UTC timezone (timestamp ends with Z).

## Collect Events from Vendor

In order to use the collector, use the XDR Collector option.

### XDR Collector
<need XDR Collector Profile here>
