Send an instruction plus incident data from an XSOAR playbook to a Hermes Agent, and read the agent's reply and tool-call trace back into the playbook context.
## Configure Hermes Agent in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Hermes API Server URL | REQUIRED. http://&lt;hermes-host-ip&gt;:8642 — no trailing slash, no /v1 on the end. Confirm the port with "grep '^API_SERVER_PORT=' ~/.hermes/.env" on the Hermes host. If API_SERVER_HOST is 127.0.0.1 then XSOAR cannot reach it at all: set it to 0.0.0.0 and restart with "systemctl --user restart hermes-gateway.service". This is the API server port, NOT the webhook port. Use https:// only if you have put a TLS reverse proxy in front - Hermes itself serves plain HTTP. Deliberately has no default: a loopback address cannot work from a remote XSOAR, so any value shipped here would be wrong. See the Help tab, Steps 1 and 3. | False |
| API Server Key | REQUIRED. On the Hermes host run: grep '^API_SERVER_KEY=' ~/.hermes/.env \| cut -d= -f2. It must be at least 16 characters — below that Hermes silently refuses to start the API server and logs nothing, so you get connection refused with no clue why. Generate one with "head -c 32 /dev/urandom \| od -An -tx1 \| tr -d ' \\n'". See the Help tab, Step 2. | True |
| Default model | Sent as the OpenAI "model" field. Leave as "hermes-agent" unless "\!hermes-models" shows something else you want. Individual commands can override it with their own model argument. | False |
| Webhook Base URL | Only needed for hermes-webhook-send; leave the default otherwise. The webhook adapter runs on its OWN port, separate from the API server above — http://&lt;hermes-host-ip&gt;:8644. Confirm it with "grep '^WEBHOOK_PORT=' ~/.hermes/.env". Reusing the 8642 URL here is the most common mistake. No default on purpose - leaving it blank makes hermes-webhook-send fail with a clear message rather than quietly posting to the API server port and returning a 404 that looks like a missing route. | False |
| Default webhook route | Name of a route defined under platforms.webhook.extra.routes in ~/.hermes/config.yaml. Produces POST /webhooks/&lt;route&gt;. The route has to exist before you can post to it, otherwise you get a 404 — the Help tab Step 5 has a config example. Individual commands can override this. | False |
| Webhook Secret | Only for hermes-webhook-send. Copy the "secret" value of your route from platforms.webhook.extra.routes in ~/.hermes/config.yaml \(or the global webhook secret if the route has none\). It signs each request; a mismatch gives 401 "Invalid signature". | False |
| Webhook signature scheme | Must match what the route expects. Leave on v2 unless you know otherwise — it is the only scheme with replay protection, and it rejects requests whose timestamp is more than 5 minutes off, so the XSOAR and Hermes clocks need to agree. Use "none" only for a route with no secret on a trusted network. | False |
| Request timeout (seconds) | How long to wait for a synchronous agent turn before giving up. An agent that reads files or browses can easily take minutes. This is only half the setting — the XSOAR playbook task has its own timeout under Task → Advanced, and the shorter of the two wins. | False |
| Trust any certificate (not secure) | Only relevant if you put Hermes behind an HTTPS proxy with a self-signed certificate. Leave off for plain http:// URLs — it does nothing there. | False |
| Use system proxy settings | Route requests through the proxy configured on the XSOAR server or engine. Leave off when Hermes is on your own network, which is the usual case. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### hermes-run

***
Runs a synchronous agent turn and returns the reply to the playbook. Uses POST /v1/chat/completions.

#### Base Command

`hermes-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The instruction for the agent. Keep untrusted incident content out of this argument - put it in "data". | Required | 
| data | Incident content for the agent to analyse. Fenced as untrusted input unless wrap_untrusted is false. | Optional | 
| system | Optional system message prepended to the turn. | Optional | 
| model | Model override for this turn. | Optional | 
| wrap_untrusted | Fence the "data" argument in an untrusted-content block so the agent does not follow instructions embedded in incident content. Possible values are: true, false. Default is true. | Optional | 
| incident_id | Incident ID recorded in the prompt provenance header. Auto-detected when the command runs inside an incident. | Optional | 
| incident_name | Incident name recorded in the prompt provenance header. | Optional | 
| severity | Severity recorded in the prompt provenance header. | Optional | 
| playbook | Playbook name recorded in the prompt provenance header. | Optional | 
| timeout | Per-command timeout in seconds. Overrides the instance setting. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hermes.Run.Reply | String | The agent's reply text. | 
| Hermes.Run.Model | String | Model reported by Hermes. | 
| Hermes.Run.ID | String | Chat completion ID. | 
| Hermes.Run.FinishReason | String | Why the turn ended. | 
| Hermes.Run.PromptTokens | Number | Prompt tokens consumed. | 
| Hermes.Run.CompletionTokens | Number | Completion tokens produced. | 
| Hermes.Run.TotalTokens | Number | Total tokens for the turn. | 

### hermes-respond

***
Runs a synchronous agent turn via the Responses API and returns both the reply and the tool-call trace, which is useful as War Room evidence. Uses POST /v1/responses.

#### Base Command

`hermes-respond`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The instruction for the agent. | Required | 
| data | Incident content for the agent to analyse. Fenced as untrusted input unless wrap_untrusted is false. | Optional | 
| instructions | System-level instructions for the run. | Optional | 
| model | Model override for this run. | Optional | 
| store | Ask Hermes to persist the response so it can be chained with previous_response_id. Possible values are: true, false. Default is false. | Optional | 
| previous_response_id | Continue from a stored response, keeping session state across playbook tasks. | Optional | 
| wrap_untrusted | Fence the "data" argument in an untrusted-content block. Possible values are: true, false. Default is true. | Optional | 
| incident_id | Incident ID recorded in the prompt provenance header. | Optional | 
| incident_name | Incident name recorded in the prompt provenance header. | Optional | 
| severity | Severity recorded in the prompt provenance header. | Optional | 
| playbook | Playbook name recorded in the prompt provenance header. | Optional | 
| timeout | Per-command timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hermes.Response.ID | String | Response ID, usable as previous_response_id when store is true. | 
| Hermes.Response.Status | String | Response status, for example completed. | 
| Hermes.Response.Model | String | Model reported by Hermes. | 
| Hermes.Response.Text | String | Assistant text output. | 
| Hermes.Response.ToolCalls.Name | String | Name of the tool the agent called. | 
| Hermes.Response.ToolCalls.Arguments | String | Arguments the agent passed to the tool. | 
| Hermes.Response.ToolCalls.Output | String | Output the tool returned. | 
| Hermes.Response.ToolCalls.CallID | String | Correlation ID for the tool call. | 
| Hermes.Response.InputTokens | Number | Input tokens consumed. | 
| Hermes.Response.OutputTokens | Number | Output tokens produced. | 
| Hermes.Response.TotalTokens | Number | Total tokens for the run. | 

### hermes-run-create

***
Starts an agent run and returns immediately with a run ID, so the playbook does not block. Fetch the result later with hermes-run-get. Uses POST /v1/runs.

#### Base Command

`hermes-run-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The instruction for the agent. | Required | 
| data | Incident content for the agent to analyse. | Optional | 
| model | Model override for this run. | Optional | 
| wrap_untrusted | Fence the "data" argument in an untrusted-content block. Possible values are: true, false. Default is true. | Optional | 
| incident_id | Incident ID recorded in the prompt provenance header. | Optional | 
| incident_name | Incident name recorded in the prompt provenance header. | Optional | 
| severity | Severity recorded in the prompt provenance header. | Optional | 
| playbook | Playbook name recorded in the prompt provenance header. | Optional | 
| timeout | Per-command timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hermes.AsyncRun.RunID | String | Run ID to pass to hermes-run-get. | 
| Hermes.AsyncRun.Status | String | Run status at creation time, normally "started". | 
| Hermes.AsyncRun.Done | Boolean | Always false here - the run has only just been queued. | 
| Hermes.AsyncRun.Model | String | Model the run is using. | 

### hermes-run-get

***
Fetches the current state and output of a run started by hermes-run-create. A single on-demand read - it does not poll on its own. Drive it from the built-in GenericPolling playbook, keying on Hermes.AsyncRun.Done. Uses GET /v1/runs/{run_id}.

#### Base Command

`hermes-run-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| run_id | Run ID returned by hermes-run-create. | Required | 
| timeout | Per-command timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hermes.AsyncRun.RunID | String | Run ID. | 
| Hermes.AsyncRun.Status | String | Current run status: queued, running, waiting_for_approval, stopping, completed, failed or cancelled. | 
| Hermes.AsyncRun.Done | Boolean | True once the run reached a terminal state \(completed, failed or cancelled\). Use this as the GenericPolling stop condition instead of enumerating states. | 
| Hermes.AsyncRun.Text | String | The agent's final answer, once the run has completed. | 
| Hermes.AsyncRun.Error | String | Failure detail when the status is failed. | 
| Hermes.AsyncRun.Model | String | Model the run used. | 
| Hermes.AsyncRun.LastEvent | String | Most recent lifecycle event, useful for seeing where a slow run is. | 
| Hermes.AsyncRun.TotalTokens | Number | Total tokens consumed by the run. | 
| Hermes.AsyncRun.ToolCalls.Name | String | Name of the tool the agent called. | 
| Hermes.AsyncRun.ToolCalls.Arguments | String | Arguments the agent passed to the tool. | 
| Hermes.AsyncRun.ToolCalls.Output | String | Output the tool returned. | 

### hermes-run-stop

***
Interrupts a running agent run. Uses POST /v1/runs/{run_id}/stop.

#### Base Command

`hermes-run-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| run_id | Run ID to interrupt. | Required | 
| timeout | Per-command timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hermes.AsyncRun.RunID | String | Run ID. | 
| Hermes.AsyncRun.Status | String | Status after the stop request. | 

### hermes-webhook-send

***
Posts a signed payload to a Hermes webhook route, which runs the agent asynchronously and routes the reply per the route's deliver setting. Fire-and-forget - nothing comes back to the playbook. Uses POST /webhooks/{route}.

#### Base Command

`hermes-webhook-send`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The instruction for the agent, sent as both "prompt" and "message" in the payload. | Required | 
| data | Incident content for the agent to analyse. | Optional | 
| route | Webhook route name. Defaults to the instance's default route. | Optional | 
| deliver | Ask the route to deliver the reply rather than only ingesting the event. Possible values are: true, false. | Optional | 
| channel | Delivery channel understood by the route, for example slack or telegram. | Optional | 
| to | Delivery recipient understood by the route. | Optional | 
| extra_fields | Additional payload fields as a JSON object, for matching route filters. For example {"event":"containment"}. | Optional | 
| wrap_untrusted | Fence the "data" argument in an untrusted-content block. Possible values are: true, false. Default is true. | Optional | 
| incident_id | Incident ID included in the payload and the prompt provenance header. | Optional | 
| incident_name | Incident name included in the payload. | Optional | 
| severity | Severity included in the payload. | Optional | 
| playbook | Playbook name included in the payload. | Optional | 
| timeout | Per-command timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hermes.Webhook.Accepted | Boolean | True when the webhook adapter accepted the payload. | 
| Hermes.Webhook.StatusCode | Number | HTTP status returned by the webhook adapter. | 
| Hermes.Webhook.Route | String | Route the payload was posted to. | 
| Hermes.Webhook.Signature | String | Signature scheme used. | 

### hermes-models

***
Lists the models the Hermes API server exposes. Uses GET /v1/models.

#### Base Command

`hermes-models`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeout | Per-command timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hermes.Model.ID | String | Model identifier. | 
| Hermes.Model.OwnedBy | String | Model owner. | 
| Hermes.Model.Object | String | Object type. | 
