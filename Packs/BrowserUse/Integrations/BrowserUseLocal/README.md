# Browser Use Local

Runs the open-source [`browser-use`](https://github.com/browser-use/browser-use) agent locally. Chromium and the LLM client both execute **inside the integration container** — perfect when you must keep traffic on-prem or want to bring your own LLM key.

For high-throughput, stealth, residential proxies, recordings, and fully managed scale, prefer the companion **Browser Use** (cloud) integration in this pack.

This integration was integrated and tested with `browser-use` 0.3.x.

## Configure Browser Use Local on Cortex

| Parameter | Description | Required |
| --- | --- | --- |
| LLM Provider | `browser-use`, `anthropic`, `google`, or `openai`. | True |
| LLM API Key | Provider-specific API key. Optional only when provider is `browser-use` and the container already has `BROWSER_USE_API_KEY`. | False |
| Default model | Provider-specific model name. Defaults: `browser-use/bu-30b-a3b-preview`, `claude-sonnet-4-6`, `gemini-3-flash-preview`, `gpt-4o`. | False |
| Default headless mode | Run Chromium headless. Stay `true` (the container has no display). | False |
| Default max steps | Hard cap on agent reasoning steps per task. | False |
| Use Browser Use Cloud stealth browser | Hybrid mode: OSS Agent here, browser runs on Browser Use Cloud. | False |
| Browser Use Cloud API Key | Required only when "Use Browser Use Cloud stealth browser" is enabled. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Commands

You can execute these commands from the Cortex CLI, as part of an automation, or in a playbook.

### browser-use-local-agent-run

***
Runs an AI browser-automation task locally.

#### Base Command

`browser-use-local-agent-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task | Natural-language instruction. | Required |
| model | Override default model for this task only. | Optional |
| llm_provider | Override default LLM provider for this task only. | Optional |
| max_steps | Override per-task max-steps cap. | Optional |
| headless | Override default headless mode. | Optional |
| use_cloud_browser | Override default "use Browser Use Cloud stealth browser". | Optional |
| output_schema | JSON-Schema string. When provided, the agent returns structured data conforming to this schema in `FinalOutput`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BrowserUseLocal.AgentRun.Task | String | Natural-language task. |
| BrowserUseLocal.AgentRun.Provider | String | LLM provider used. |
| BrowserUseLocal.AgentRun.Model | String | Model used. |
| BrowserUseLocal.AgentRun.FinalOutput | Unknown | Final output (text or structured JSON if `output_schema` was provided). |
| BrowserUseLocal.AgentRun.IsDone | Boolean | Whether the agent reached a terminal state. |
| BrowserUseLocal.AgentRun.IsSuccessful | Boolean | Whether the agent reports success (may be null). |
| BrowserUseLocal.AgentRun.VisitedUrls | Unknown | URLs visited during the run. |

### browser-use-local-screenshot

***
Takes a single screenshot of a URL using local headless Chromium (no LLM). Returns a War Room file entry.

#### Base Command

`browser-use-local-screenshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to capture. | Required |
| wait_seconds | Seconds to wait after page load. Default `0`. | Optional |
| full_page | Capture the full scrollable page rather than just the viewport. Default `true`. | Optional |
| headless | Override default headless mode. | Optional |

### browser-use-local-version

***
Reports the installed `browser-use` library version.

#### Base Command

`browser-use-local-version`

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BrowserUseLocal.Version.BrowserUseVersion | String | Installed `browser-use` library version. |

## Notes

- Each `browser-use-local-agent-run` invocation spawns Chromium for the duration of the task — heavy and serial. Use the cloud integration in this same pack for parallel / high-throughput workflows.
- The integration ships with a reference [`Dockerfile`](Dockerfile) showing how to build the `demisto/browser-use:*` image (Playwright + Chromium + `browser-use` + LLM SDKs).
