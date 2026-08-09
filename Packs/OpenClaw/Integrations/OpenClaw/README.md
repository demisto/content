Send an instruction plus incident data from an XSOAR playbook to an OpenClaw agent, and read the agent's reply back into the playbook context.
## Configure OpenClaw in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| OpenClaw Gateway URL | REQUIRED. Run "openclaw gateway status" on the Gateway host and copy the address on the Dashboard line, without the trailing slash — for example http://192.0.2.10:18789. If that line shows 127.0.0.1 or says bind=loopback, XSOAR cannot reach it: run "openclaw config set gateway.bind lan" then "openclaw gateway restart" first. Use https:// only if you have put a TLS reverse proxy in front - the Gateway itself serves plain HTTP. Deliberately has no default: any value shipped here would be wrong for your network, and a loopback default cannot work from XSOAR anyway. See the Help tab, Step 1. | True |
| Gateway Auth Token | REQUIRED. On the Gateway host run: jq -r '.gateway.auth.token' ~/.openclaw/openclaw.json — do NOT use "openclaw config get gateway.auth.token", which prints \__OPENCLAW_REDACTED_\_ instead of the real value and will fail with a 401. If it prints null, create one with "openclaw config set gateway.auth.token \\"$\(openssl rand -hex 24\)\\"" and restart the Gateway. Used by openclaw-run and openclaw-tool-invoke. See the Help tab, Step 2. | True |
| Hooks Token | Only needed for openclaw-hook-agent and openclaw-hook-wake. Leave blank if you only use openclaw-run. Get it with: jq -r '.hooks.token' ~/.openclaw/openclaw.json — null means hooks are switched off, and the Help tab Step 5 has the command that enables them. Keep this DIFFERENT from the Gateway Auth Token; blank falls back to it, which OpenClaw advises against. | False |
| Default agent ID | Which agent handles requests that do not name one. Run "openclaw agents list" on the Gateway host and use the entry marked \(default\). "main" is the standard name. | False |
| Default model | Leave as "openclaw" to let the Gateway pick, which is almost always what you want. Use "openclaw:&lt;agentId&gt;" to pin one agent, or a provider model id to override — that id must appear in agents.defaults.models if the Gateway restricts models, otherwise the request is rejected. | False |
| Hooks path | Must match hooks.path on the Gateway. Check with: jq -r '.hooks.path' ~/.openclaw/openclaw.json. Almost always /hooks — change it only if somebody customised it, or the hook commands return 404. | False |
| Request timeout (seconds) | How long to wait for a synchronous agent turn before giving up. An agent that reads files or browses can easily take minutes. This is only half the setting — the XSOAR playbook task has its own timeout under Task → Advanced, and the shorter of the two wins. | False |
| Trust any certificate (not secure) | Only relevant if you put the Gateway behind an HTTPS proxy with a self-signed certificate. Leave off for plain http:// URLs — it does nothing there. | False |
| Use system proxy settings | Route requests through the proxy configured on the XSOAR server or engine. Leave off when the Gateway is on your own network, which is the usual case. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### openclaw-run

***
Runs a synchronous agent turn on the OpenClaw Gateway and returns the agent's reply to the playbook. Uses POST /v1/chat/completions, which must be enabled on the Gateway.

#### Base Command

`openclaw-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The instruction for the agent. Keep untrusted incident content out of this argument - put it in "data". | Required | 
| data | Incident content for the agent to analyse (alert JSON, log lines, an email body). Fenced as untrusted input unless wrap_untrusted is false. | Optional | 
| system | Optional system message prepended to the turn. | Optional | 
| agent_id | Agent to route to. Defaults to the instance's default agent ID. | Optional | 
| model | Model override for this turn. Must be permitted by agents.defaults.models if the Gateway restricts models. | Optional | 
| session_key | Explicit session key, sent as the x-openclaw-session-key header. When omitted, calls for the same incident share a session derived from the incident ID. | Optional | 
| wrap_untrusted | Fence the "data" argument in an untrusted-content block so the agent does not follow instructions embedded in incident content. Possible values are: true, false. Default is true. | Optional | 
| incident_id | Incident ID recorded in the prompt provenance header. Auto-detected when the command runs inside an incident. | Optional | 
| incident_name | Incident name recorded in the prompt provenance header. | Optional | 
| severity | Severity recorded in the prompt provenance header. | Optional | 
| playbook | Playbook name recorded in the prompt provenance header. | Optional | 
| timeout | Per-command timeout in seconds. Overrides the instance setting. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenClaw.Run.Reply | String | The agent's reply text. | 
| OpenClaw.Run.AgentID | String | Agent that handled the turn. | 
| OpenClaw.Run.Model | String | Model reported by the Gateway. | 
| OpenClaw.Run.SessionKey | String | Session key used for the turn. | 
| OpenClaw.Run.ID | String | Chat completion ID. | 
| OpenClaw.Run.FinishReason | String | Why the turn ended, for example stop or length. | 
| OpenClaw.Run.PromptTokens | Number | Prompt tokens consumed. | 
| OpenClaw.Run.CompletionTokens | Number | Completion tokens produced. | 
| OpenClaw.Run.TotalTokens | Number | Total tokens for the turn. | 

### openclaw-hook-agent

***
Starts an isolated agent run and returns immediately (HTTP 202). The reply is not returned to the playbook - set deliver=true with a channel to push it to a chat surface. Uses POST /hooks/agent.

#### Base Command

`openclaw-hook-agent`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The instruction for the agent. | Required | 
| data | Incident content for the agent to analyse. Fenced as untrusted input unless wrap_untrusted is false. | Optional | 
| name | Human-readable hook name, used as a prefix in session summaries. Default is XSOAR. | Optional | 
| agent_id | Agent to route to. Must be permitted by hooks.allowedAgentIds when that list is set. | Optional | 
| deliver | Send the agent's reply to a messaging channel. Possible values are: true, false. Default is false. | Optional | 
| channel | Messaging channel for delivery. Possible values are: last, whatsapp, telegram, discord, slack, mattermost, signal, imessage, msteams. Default is last. | Optional | 
| to | Recipient for the channel - a phone number for WhatsApp/Signal, a chat ID for Telegram, channel:&lt;id&gt; for Slack/Discord, a conversation ID for MS Teams. Defaults to the last recipient in the main session. | Optional | 
| wake_mode | Trigger an immediate heartbeat or wait for the next periodic one. Possible values are: now, next-heartbeat. Default is now. | Optional | 
| session_key | Explicit session key. Rejected by the Gateway unless hooks.allowRequestSessionKey is true. | Optional | 
| model | Model override for the run. | Optional | 
| thinking | Thinking level override. Possible values are: off, low, medium, high. | Optional | 
| agent_timeout_seconds | Maximum duration of the agent run on the Gateway. Separate from the HTTP request timeout. | Optional | 
| wrap_untrusted | Fence the "data" argument in an untrusted-content block. Possible values are: true, false. Default is true. | Optional | 
| incident_id | Incident ID recorded in the prompt provenance header. | Optional | 
| incident_name | Incident name recorded in the prompt provenance header. | Optional | 
| severity | Severity recorded in the prompt provenance header. | Optional | 
| playbook | Playbook name recorded in the prompt provenance header. | Optional | 
| timeout | Per-command HTTP timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenClaw.Hook.Accepted | Boolean | True when the Gateway returned HTTP 202. | 
| OpenClaw.Hook.StatusCode | Number | HTTP status returned by the Gateway. | 
| OpenClaw.Hook.AgentID | String | Agent the hook was routed to. | 
| OpenClaw.Hook.Name | String | Hook name sent to the Gateway. | 
| OpenClaw.Hook.Delivered | Boolean | Whether the reply was requested to be delivered to a channel. | 
| OpenClaw.Hook.Channel | String | Delivery channel. | 
| OpenClaw.Hook.To | String | Delivery recipient. | 

### openclaw-hook-wake

***
Enqueues a system event on the Gateway's main session, optionally triggering an immediate heartbeat. Use it to tell the agent that something happened without asking it to do work. Uses POST /hooks/wake.

#### Base Command

`openclaw-hook-wake`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Description of the event, for example "XSOAR incident 4821 escalated to critical". | Required | 
| mode | Trigger an immediate heartbeat or wait for the next periodic one. Possible values are: now, next-heartbeat. Default is now. | Optional | 
| timeout | Per-command HTTP timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenClaw.Wake.Accepted | Boolean | True when the Gateway accepted the event. | 
| OpenClaw.Wake.StatusCode | Number | HTTP status returned by the Gateway. | 
| OpenClaw.Wake.Mode | String | Wake mode requested. | 

### openclaw-tool-invoke

***
Invokes a single OpenClaw tool directly, with no agent turn. Subject to the Gateway's tool policy; a tool that policy blocks returns HTTP 404. Uses POST /tools/invoke.

#### Base Command

`openclaw-tool-invoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tool | Tool name, for example sessions_list. | Required | 
| action | Action mapped into the tool arguments when the tool schema supports it, for example json. | Optional | 
| tool_args | Tool arguments as a JSON object, for example {"limit": 10}. | Optional | 
| session_key | Target session key. Omit or use "main" for the configured main session. | Optional | 
| message_channel | Channel hint for group policy resolution, sent as x-openclaw-message-channel. | Optional | 
| account_id | Account hint sent as x-openclaw-account-id, when several accounts exist. | Optional | 
| timeout | Per-command HTTP timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenClaw.Tool.Name | String | Tool that was invoked. | 
| OpenClaw.Tool.OK | Boolean | Whether the Gateway reported success. | 
| OpenClaw.Tool.Result | Unknown | Tool result payload. | 
