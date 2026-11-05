Respond to AI agent threats in NVIDIA OpenShell sandboxes: stop or suspend a sandbox, block its egress to a host, and detach its credentials.
This integration was integrated and tested with version 0.1.6 of NVIDIA OpenShell.

## Configure NVIDIA OpenShell in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Gateway endpoint (host:port) | The OpenShell gateway gRPC endpoint. The gateway is usually private, so run this integration on an engine that can reach it. | True |
| Workspace | The default OpenShell workspace for commands that do not specify one. | False |
| Gateway CA certificate | The PEM CA certificate that signed the gateway certificate \(ca.crt\). | False |
| Client certificate | The PEM client certificate for mutual TLS \(tls.crt\). | False |
| Client private key | The PEM private key of the client certificate \(tls.key\). | False |
| OIDC bearer token | The OIDC access token. Only for gateways configured for OIDC authentication. | False |
| Plaintext gateway (no TLS) | Whether to connect without TLS. Not secure. Use only for test gateways that do not use TLS. | False |
| Timeout (seconds) | The number of seconds to wait for each gateway call. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### openshell-gateway-info-get

***
Returns the OpenShell gateway version and information.

#### Base Command

`openshell-gateway-info-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Gateway.Endpoint | String | The gateway endpoint. | 
| OpenShell.Gateway.Version | String | The gateway version. | 
| OpenShell.Gateway.Info | Unknown | The gateway information returned by the gateway. | 

### openshell-sandbox-list

***
Lists sandboxes and their phase.

#### Base Command

`openshell-sandbox-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| all_workspaces | Whether to list sandboxes across all workspaces. Possible values are: true, false. Default is false. | Optional | 
| label_selector | The Kubernetes-style label selector to filter sandboxes by, for example team=ml. | Optional | 
| limit | The maximum number of sandboxes to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Sandbox.ID | String | The sandbox ID. | 
| OpenShell.Sandbox.Name | String | The sandbox name. | 
| OpenShell.Sandbox.Workspace | String | The sandbox workspace. | 
| OpenShell.Sandbox.Phase | String | The sandbox phase, for example READY, STOPPED or SUSPENDED. | 
| OpenShell.Sandbox.PolicyVersion | Number | The active policy version. | 
| OpenShell.Sandbox.Labels | Unknown | The sandbox labels. | 

### openshell-sandbox-get

***
Returns a single sandbox.

#### Base Command

`openshell-sandbox-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Sandbox.ID | String | The sandbox ID. | 
| OpenShell.Sandbox.Name | String | The sandbox name. | 
| OpenShell.Sandbox.Workspace | String | The sandbox workspace. | 
| OpenShell.Sandbox.Phase | String | The sandbox phase, for example READY, STOPPED or SUSPENDED. | 
| OpenShell.Sandbox.PolicyVersion | Number | The active policy version. | 
| OpenShell.Sandbox.Labels | Unknown | The sandbox labels. | 

### openshell-sandbox-stop

***
Stops a sandbox. The agent stops running. Its identity and workspace are kept, so it can be started again after the investigation.

#### Base Command

`openshell-sandbox-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| wait | Whether to wait until the sandbox reports STOPPED. Possible values are: true, false. Default is true. | Optional | 
| timeout_seconds | The number of seconds to wait for the sandbox to stop. Default is 120. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Sandbox.ID | String | The sandbox ID. | 
| OpenShell.Sandbox.Name | String | The sandbox name. | 
| OpenShell.Sandbox.Workspace | String | The sandbox workspace. | 
| OpenShell.Sandbox.Phase | String | The sandbox phase, for example READY, STOPPED or SUSPENDED. | 
| OpenShell.Sandbox.PolicyVersion | Number | The active policy version. | 
| OpenShell.Sandbox.Labels | Unknown | The sandbox labels. | 
| OpenShell.Sandbox.Action | String | The action that was requested. | 

### openshell-sandbox-start

***
Starts a stopped sandbox.

#### Base Command

`openshell-sandbox-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Sandbox.ID | String | The sandbox ID. | 
| OpenShell.Sandbox.Name | String | The sandbox name. | 
| OpenShell.Sandbox.Workspace | String | The sandbox workspace. | 
| OpenShell.Sandbox.Phase | String | The sandbox phase, for example READY, STOPPED or SUSPENDED. | 
| OpenShell.Sandbox.PolicyVersion | Number | The active policy version. | 
| OpenShell.Sandbox.Labels | Unknown | The sandbox labels. | 
| OpenShell.Sandbox.Action | String | The action that was requested. | 

### openshell-sandbox-suspend

***
Suspends a sandbox and keeps its state. Requires a sandbox driver that supports suspend.

#### Base Command

`openshell-sandbox-suspend`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Sandbox.ID | String | The sandbox ID. | 
| OpenShell.Sandbox.Name | String | The sandbox name. | 
| OpenShell.Sandbox.Workspace | String | The sandbox workspace. | 
| OpenShell.Sandbox.Phase | String | The sandbox phase, for example READY, STOPPED or SUSPENDED. | 
| OpenShell.Sandbox.PolicyVersion | Number | The active policy version. | 
| OpenShell.Sandbox.Labels | Unknown | The sandbox labels. | 
| OpenShell.Sandbox.Action | String | The action that was requested. | 

### openshell-sandbox-resume

***
Resumes a suspended sandbox.

#### Base Command

`openshell-sandbox-resume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Sandbox.ID | String | The sandbox ID. | 
| OpenShell.Sandbox.Name | String | The sandbox name. | 
| OpenShell.Sandbox.Workspace | String | The sandbox workspace. | 
| OpenShell.Sandbox.Phase | String | The sandbox phase, for example READY, STOPPED or SUSPENDED. | 
| OpenShell.Sandbox.PolicyVersion | Number | The active policy version. | 
| OpenShell.Sandbox.Labels | Unknown | The sandbox labels. | 
| OpenShell.Sandbox.Action | String | The action that was requested. | 

### openshell-sandbox-delete

***
Deletes a sandbox. This action cannot be undone.

#### Base Command

`openshell-sandbox-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| confirm | Whether to confirm the action, which cannot be undone. Set to yes to run it. Possible values are: yes, no. | Required | 
| allow_missing | Whether to succeed if the sandbox does not exist. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Sandbox.Name | String | The sandbox name. | 
| OpenShell.Sandbox.ID | String | The sandbox ID. | 
| OpenShell.Sandbox.Outcome | String | The deletion outcome. | 
| OpenShell.Sandbox.Action | String | The action that was requested. | 

### openshell-sandbox-logs

***
Returns recent sandbox log lines, such as network decisions, process and policy events.

#### Base Command

`openshell-sandbox-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| lines | The number of log lines to return. Default is 200. | Optional | 
| min_level | The minimum log level to return, for example WARN. | Optional | 
| sources | The comma-separated list of log sources to include. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Log.Sandbox | String | The sandbox name. | 
| OpenShell.Log.Time | Date | The event time. | 
| OpenShell.Log.Level | String | The log level. | 
| OpenShell.Log.Source | String | The log source. | 
| OpenShell.Log.Target | String | The log target. | 
| OpenShell.Log.Message | String | The log message. | 

### openshell-policy-get

***
Returns the current network policy of a sandbox: rules, hosts, ports and allowed binaries.

#### Base Command

`openshell-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Policy.Sandbox | String | The sandbox name. | 
| OpenShell.Policy.Version | Number | The policy version. | 
| OpenShell.Policy.PolicyHash | String | The policy hash. | 
| OpenShell.Policy.NetworkRules.Rule | String | The network rule name. | 
| OpenShell.Policy.NetworkRules.Host | String | The allowed host. | 
| OpenShell.Policy.NetworkRules.Ports | Number | The allowed ports. | 
| OpenShell.Policy.NetworkRules.Protocol | String | The protocol. | 
| OpenShell.Policy.NetworkRules.Path | String | The allowed path. | 
| OpenShell.Policy.NetworkRules.Binaries | String | The binaries allowed to use the rule. | 

### openshell-policy-history

***
Returns the policy revisions of a sandbox, newest first.

#### Base Command

`openshell-policy-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| limit | The maximum number of revisions to return. Default is 20. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.PolicyRevision.Sandbox | String | The sandbox name. | 
| OpenShell.PolicyRevision.Version | Number | The policy version. | 
| OpenShell.PolicyRevision.Status | String | The revision status. | 
| OpenShell.PolicyRevision.Hash | String | The policy hash. | 
| OpenShell.PolicyRevision.LoadError | String | The load error, if the revision failed to load. | 
| OpenShell.PolicyRevision.Created | Date | The time the revision was created. | 

### openshell-egress-block-host

***
Removes every allow entry for a host from the sandbox network policy, so the agent can no longer reach that host. The sandbox keeps running.

#### Base Command

`openshell-egress-block-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| host | The destination host, for example files.example.com. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| reason | The reason for the change, recorded on the new policy revision. Default is Cortex response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.PolicyChange.Sandbox | String | The sandbox name. | 
| OpenShell.PolicyChange.NewVersion | Number | The new policy version. | 
| OpenShell.PolicyChange.PolicyHash | String | The hash of the new policy. | 
| OpenShell.PolicyChange.Change | String | A summary of the change. | 

### openshell-policy-rule-remove

***
Removes a network rule from the sandbox policy. All destinations of the rule are denied.

#### Base Command

`openshell-policy-rule-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| rule_name | The network rule name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| reason | The reason for the change, recorded on the new policy revision. Default is Cortex response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.PolicyChange.Sandbox | String | The sandbox name. | 
| OpenShell.PolicyChange.NewVersion | Number | The new policy version. | 
| OpenShell.PolicyChange.PolicyHash | String | The hash of the new policy. | 
| OpenShell.PolicyChange.Change | String | A summary of the change. | 

### openshell-policy-endpoint-remove

***
Removes a single host and port from a network rule.

#### Base Command

`openshell-policy-endpoint-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| rule_name | The network rule name. | Required | 
| host | The host to remove. | Required | 
| port | The port to remove. 0 removes the host on any port. Default is 0. | Optional | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| reason | The reason for the change, recorded on the new policy revision. Default is Cortex response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.PolicyChange.Sandbox | String | The sandbox name. | 
| OpenShell.PolicyChange.NewVersion | Number | The new policy version. | 
| OpenShell.PolicyChange.PolicyHash | String | The hash of the new policy. | 
| OpenShell.PolicyChange.Change | String | A summary of the change. | 

### openshell-policy-binary-remove

***
Removes a binary, for example /usr/bin/curl, from a network rule so it can no longer use that rule.

#### Base Command

`openshell-policy-binary-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| rule_name | The network rule name. | Required | 
| binary_path | The binary path. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| reason | The reason for the change, recorded on the new policy revision. Default is Cortex response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.PolicyChange.Sandbox | String | The sandbox name. | 
| OpenShell.PolicyChange.NewVersion | Number | The new policy version. | 
| OpenShell.PolicyChange.PolicyHash | String | The hash of the new policy. | 
| OpenShell.PolicyChange.Change | String | A summary of the change. | 

### openshell-provider-list

***
Lists the credential providers attached to a sandbox.

#### Base Command

`openshell-provider-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Provider.Sandbox | String | The sandbox name. | 
| OpenShell.Provider.Name | String | The provider name. | 
| OpenShell.Provider.Type | String | The provider type. | 
| OpenShell.Provider.Workspace | String | The provider profile workspace. | 

### openshell-provider-detach

***
Detaches a credential provider from a sandbox, so the agent no longer receives those credentials. This action cannot be undone.

#### Base Command

`openshell-provider-detach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The sandbox name. | Required | 
| provider | The provider name. | Required | 
| workspace | The OpenShell workspace. Defaults to the instance workspace. | Optional | 
| confirm | Whether to confirm the action, which cannot be undone. Set to yes to run it. Possible values are: yes, no. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenShell.Provider.Sandbox | String | The sandbox name. | 
| OpenShell.Provider.Name | String | The provider name. | 
| OpenShell.Provider.Action | String | The action that was performed. | 
