# Browser Use

AI-powered browser automation via the [Browser Use Cloud](https://browser-use.com) API (v3).

Send a natural-language task; an LLM agent (Claude Opus 4.6, Claude Sonnet 4.6, or Gemini 3 Flash) drives a stealth Chromium browser to complete it. Residential proxies, CAPTCHA solving, recordings, and persistent profiles are all built in.

This integration was integrated and tested with **Browser Use Cloud API v3**.

## Configure Browser Use on Cortex

| Parameter | Description | Required |
| --- | --- | --- |
| Server URL | Defaults to `https://api.browser-use.com`. The `/v3` path is appended automatically. | True |
| API Key | API key (starts with `bu_`) generated at <https://cloud.browser-use.com/settings?tab=api-keys>. | True |
| Default model | Default agent model used when `model` is not passed to `browser-use-task-run`. | False |
| Default max cost per task (USD) | Safety cap per task. | False |
| Default proxy country | Two-letter ISO 3166-1 alpha-2 country code (e.g. `us`, `de`, `gb`). Empty disables proxy. | False |
| Default session timeout (minutes) | 1–240. | False |
| Wait-for-completion timeout (seconds) | Used when `wait=true` is passed to `browser-use-task-run`. | False |
| Polling interval (seconds) | Used when `wait=true`. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the Cortex CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### browser-use-account-info

***
Returns account billing information — credit balances, rate limit and plan.

#### Base Command

`browser-use-account-info`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BrowserUse.Account.Name | String | Account display name. |
| BrowserUse.Account.ProjectID | String | Project ID. |
| BrowserUse.Account.TotalCreditsBalanceUsd | Number | Total credits remaining (USD). |
| BrowserUse.Account.MonthlyCreditsBalanceUsd | Number | Monthly subscription credits (USD). |
| BrowserUse.Account.AdditionalCreditsBalanceUsd | Number | Top-up credits (USD). |
| BrowserUse.Account.RateLimit | Number | Account rate limit. |
| BrowserUse.Account.Plan.Name | String | Plan name. |
| BrowserUse.Account.Plan.SubscriptionStatus | String | Subscription status. |

### browser-use-task-run

***
Dispatches a natural-language task to a Browser Use agent. Either a new agent session is created, or the task is sent to an existing idle session via `session_id`. Use `wait=true` to block until the agent reaches a terminal state.

#### Base Command

`browser-use-task-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task | Natural-language instruction for the agent. | Optional |
| session_id | Existing agent session ID to dispatch this task to (for follow-up tasks against a `keep_alive=true` session). | Optional |
| model | Override default agent model (`bu-mini`, `bu-max`, `bu-ultra`, `gemini-3-flash`, `claude-sonnet-4.6`, `claude-opus-4.6`). | Optional |
| profile_id | Browser profile to load. | Optional |
| workspace_id | Workspace to attach to the session. | Optional |
| keep_alive | Keep the session alive after the task ends so follow-up tasks can reuse it. | Optional |
| max_cost_usd | Maximum total session cost in USD before the task is auto-stopped. | Optional |
| proxy_country | ISO country code for residential proxy (overrides default). | Optional |
| session_timeout_min | Session timeout in minutes (1–240). | Optional |
| enable_recording | Enable session recording. | Optional |
| wait | Block and poll until terminal status. | Optional |
| poll_interval | Seconds between polls (overrides instance default). | Optional |
| poll_timeout | Max seconds to wait (overrides instance default). | Optional |

> Either `task` or `session_id` must be provided.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BrowserUse.Task.ID | String | Agent session ID. |
| BrowserUse.Task.Status | String | `created`, `idle`, `running`, `stopped`, `timed_out`, `error`. |
| BrowserUse.Task.Model | String | Model used. |
| BrowserUse.Task.Title | String | Auto-generated short title. |
| BrowserUse.Task.Output | Unknown | Final agent output (string or structured JSON). |
| BrowserUse.Task.IsTaskSuccessful | Boolean | Whether the agent reports success. |
| BrowserUse.Task.LiveUrl | String | URL to watch the live browser. |
| BrowserUse.Task.RecordingUrls | Unknown | Presigned recording URLs (after task ends). |
| BrowserUse.Task.TotalCostUsd | String | Total session cost (USD). |
| BrowserUse.Task.StepCount | Number | Steps executed. |
| BrowserUse.Task.LastStepSummary | String | Most recent step summary. |

### browser-use-task-get

***
Retrieves the current state of an agent task.

#### Base Command

`browser-use-task-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | Agent session ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BrowserUse.Task.ID | String | Agent session ID. |
| BrowserUse.Task.Status | String | Lifecycle status. |
| BrowserUse.Task.Output | Unknown | Final agent output. |
| BrowserUse.Task.IsTaskSuccessful | Boolean | Whether the agent reports success. |
| BrowserUse.Task.RecordingUrls | Unknown | Presigned recording URLs. |

### browser-use-task-list

***
Lists recent agent sessions.

#### Base Command

`browser-use-task-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number (1-indexed). | Optional |
| page_size | Page size. Default 50. | Optional |

### browser-use-task-stop

***
Stops a running agent task or destroys the session.

#### Base Command

`browser-use-task-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | Agent session ID. | Required |
| strategy | `task` keeps the session idle for follow-ups; `session` destroys it. Default `session`. | Optional |

### browser-use-task-messages-list

***
Lists the agent's streaming messages for a session (steps, browser actions, screenshots).

#### Base Command

`browser-use-task-messages-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | Agent session ID. | Required |
| after | Cursor — return messages after this ID. | Optional |
| before | Cursor — return messages before this ID. | Optional |
| limit | Max messages. | Optional |

### browser-use-task-screenshot-get

***
Returns a presigned URL to the most recent screenshot (~5 minute expiry).

#### Base Command

`browser-use-task-screenshot-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | Agent session ID. | Required |

### browser-use-browser-create

***
Creates a raw stealth browser session (no agent). Returns `liveUrl` to view it and `cdpUrl` to drive via Playwright/Puppeteer/Selenium.

#### Base Command

`browser-use-browser-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | Browser profile ID. | Optional |
| proxy_country | ISO country code (overrides default). | Optional |
| timeout_min | Session timeout (1–240). | Optional |
| screen_width | Viewport width (320–6144). | Optional |
| screen_height | Viewport height (320–3456). | Optional |
| allow_resizing | Allow window resize during session. | Optional |
| enable_recording | Enable session recording. | Optional |

### browser-use-browser-get / browser-use-browser-list / browser-use-browser-stop

Standard get/list/stop semantics for stealth browser sessions.

### browser-use-profile-list / -get / -create / -delete

Manage persistent browser profiles (cookies, localStorage, saved logins).

### browser-use-workspace-list / -get / -create / -delete / -files-list

Manage per-session file workspaces. `browser-use-workspace-files-list` accepts an `include_urls=true` argument to receive 60-second presigned download URLs.

## Notes

- All commands use the `/v3` Browser Use Cloud API. The legacy v2 API is *not* used.
- Costs are tracked per session and exposed under `BrowserUse.Task.*CostUsd`. Use `max_cost_usd` (or the instance default) to cap spending per task.
- Screenshot and recording URLs are short-lived presigned URLs — re-fetch them when needed.
