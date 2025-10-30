Partner Contributed Integration

Integration Author: ShadowX AI
Support: This is a partner-contributed integration. ShadowX AI is responsible for support and maintenance.

Email: info@shadowx.ai

URL: https://shadowx.ai

ShadowX SOCAI

ShadowX SOCAI filters sensitive data in security logs and analyzes them using enterprise GenAI engines (such as ChatGPT, Gemini, and Claude). It returns enriched guidance, including:

AI Response / explanation

Analyst Recommendation

Risk / result classification

Prediction score / confidence

This integration was tested against ShadowX SOCAI backend version 1.1.0.

The integration can operate in two modes:

API Key mode (recommended)

Cookie (HTML) mode

Authentication Modes
1. API Key (recommended)

In this mode, the integration uses a bearer token to call ShadowX SOCAI’s API endpoints.

Set the API Key (a service token) in the integration instance under API Key (recommended).

The integration then sends JSON to the submission endpoint (by default /Api/SecurityTasks/Create) with an Authorization: Bearer <API_KEY> header.

The API returns a TaskId.

The integration can optionally poll the task status from the check endpoint (by default /Api/SecurityTasks/Details?taskID={task_id}) until analysis is completed.

You can customize both endpoints in the instance configuration:

API Submission Path

API Check Path Format

How to obtain the API Key:
In the ShadowX SOCAI platform, generate or copy an API token that has permission to:

create Security Tasks

read Security Task details

Paste that token into the integration instance.
If an API Key is configured, the integration ignores the email/password fields.

2. Cookie (HTML) mode

If an API Key is not provided, the integration can log in using user credentials and submit a task through the web workflow.

This mode:

Logs in (JSON body) with User Email and User Password to obtain a session cookie.

Loads /SecurityTasks/Create to retrieve an anti-forgery token.

Submits the security log using that token.

Notes:

Cookie mode is often used in interactive environments where analysts already have UI access.

If your ShadowX SOCAI environment enforces SSO / redirect challenges for /SecurityTasks/Create, cookie mode may fail. In that case, use API Key mode.

Cookie mode does not currently poll for task completion.

Installation / Configuration

When creating an instance of the integration in Cortex XSOAR:

Required:

Server URL
Example: https://app.shadowx.ai or your on-prem deployment.

Authentication:

Either set API Key (recommended),

OR set User Email / User Password for cookie mode.

Optional instance parameters:

API Submission Path (default: /Api/SecurityTasks/Create)

API Check Path Format (default: /Api/SecurityTasks/Details?taskID={task_id})

AI Driver ID (GUID)

Assigned User ID (GUID)

Default Policy ID (GUID)

Default Task Name

Use system proxy settings

Trust any certificate (not secure) (for self-signed lab / PoC environments)

These optional IDs allow you to pre-assign which AI engine is used, which policy to apply, who “owns” the task, and what default task name appears in ShadowX SOCAI.

Commands
shadowx-submit-task

Submit a security log to ShadowX SOCAI for analysis.

Arguments:

log (required):
Raw log content / event text to analyze.
This can include suspicious process activity, authentication failures, etc.

ip_addr (optional):
IP address related to the event.

user_name (optional):
A username or subject for the task. In cookie mode this is also used as the task Subject.

policy_id (optional):
Overrides the Default Policy ID from the instance configuration for this one submission.

wait_seconds (optional, API Key mode only):
Maximum time (in seconds) to wait for the analysis result.
If provided and the backend returns a TaskId, the integration will poll ShadowX SOCAI until:

the task finishes, or

the timeout expires.

interval_seconds (optional, API Key mode only):
How often to poll during that wait. Defaults to 30 seconds.
Only used if wait_seconds > 0.

Behavior:

In API Key mode:

The command creates a task using /Api/SecurityTasks/Create (or your configured path).

The response includes TaskId and a UI URL like
https://<your-server>/SecurityTasks/Details?taskID=<TaskId>.

If wait_seconds > 0, the command calls the check endpoint (by default /Api/SecurityTasks/Details?taskID={task_id}) in a loop until the task is marked complete or the timeout is reached.

If the final task data is retrieved, it is returned under ShadowxSOCAI.TaskResult.

In Cookie mode:

The command logs in with the provided credentials, obtains the anti-forgery token, and submits the task through the HTML flow.

Cookie mode does not poll for completion; it returns the submitted TaskId and Task URL.

Outputs (Context):

ShadowxSOCAI.TaskSubmit.TaskId

ShadowxSOCAI.TaskSubmit.TaskURL

ShadowxSOCAI.TaskResult.TaskId

ShadowxSOCAI.TaskResult.TaskName

ShadowxSOCAI.TaskResult.AssignedUserName

ShadowxSOCAI.TaskResult.AIDriverName

ShadowxSOCAI.TaskResult.PolicyName

ShadowxSOCAI.TaskResult.Subject

ShadowxSOCAI.TaskResult.SecurityLog

ShadowxSOCAI.TaskResult.SanitizedLog

ShadowxSOCAI.TaskResult.Response

ShadowxSOCAI.TaskResult.Recommendation

ShadowxSOCAI.TaskResult.Status

ShadowxSOCAI.TaskResult.RiskSeverity

ShadowxSOCAI.TaskResult.PredictionScore

These map directly to the enriched SOC triage context provided by ShadowX SOCAI.

Examples:

!shadowx-submit-task log="Failed login from 192.168.1.10 for svc-admin"

!shadowx-submit-task log="Suspicious lsass access by kedi.exe" ip_addr="203.0.113.45" user_name="test-user" wait_seconds=180 interval_seconds=30


In the second example:

The task is submitted.

The integration waits (up to 180 seconds, polling every 30 seconds) for a completed analysis.

If successful, the final AI assessment appears in the War Room and in context.

shadowx-get-task

Retrieve task details for an existing ShadowX SOCAI task (API Key mode).

Arguments:

task_id (required):
The Task GUID returned by shadowx-submit-task or visible in the ShadowX SOCAI UI.

Behavior:

Uses the configured API Key to call the check endpoint (by default /Api/SecurityTasks/Details?taskID={task_id}).

Parses and returns a normalized structure with task metadata, AI response, classification, and recommendation.

Also attempts to push those fields to the incident (for easier analyst triage).

Example:

!shadowx-get-task task_id="26482f44-4c5d-41e2-94d6-2a3c12098e14"

Troubleshooting

401 Invalid API key
The API Key in the instance is missing, expired, or does not have permission to create/read tasks.
Generate a valid service token in ShadowX SOCAI and update the instance configuration.

302 / redirect loop in cookie mode
The environment enforces SSO or domain-based cookies.
Make sure that the Server URL you configured in XSOAR matches the domain you normally use to access ShadowX SOCAI in the browser (cookies are domain-scoped).
If SSO is enforced and you can’t get a session cookie via /User/Login, use API Key mode.

Self-signed certificate / lab environment
Enable Trust any certificate (not secure) in the instance to allow requests to proceed against self-signed TLS certs.

Proxy / outbound restriction
If XSOAR needs to go through an outbound proxy, enable Use system proxy settings.

Note: This pack is partner-supported. For support or feature requests (including new policy mappings or model behaviors), contact info@shadowx.ai.
