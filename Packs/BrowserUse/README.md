# Browser Use

[Browser Use](https://browser-use.com) drives a Chromium browser with an LLM agent so you can automate web tasks with natural-language instructions. It comes in two flavors:

- a **fully managed Cloud** with stealth Chromium, residential proxies in 195+ countries, CAPTCHA solving, recordings, and persistent profiles, and
- an **open-source Python library** ([`browser-use`](https://github.com/browser-use/browser-use)) you can self-host.

This pack ships **two integrations**, one for each:

| Integration | When to use it | Where Chromium runs | Auth |
| --- | --- | --- | --- |
| **Browser Use** | High-throughput, stealth, residential proxies, recordings, persistent profiles, vendor-managed scaling. | Browser Use Cloud | One `bu_...` API key |
| **Browser Use Local** | Air-gapped / on-prem, BYO LLM key (Anthropic / Google / OpenAI / Browser Use), full code control. | Inside the integration container | Your LLM provider key (and optionally a Browser Use Cloud key for the hybrid stealth-browser mode) |

## What you can do with it

- **Safe URL detonation / phishing triage** — open a suspicious URL in a sandboxed stealth browser, screenshot it, and ask the agent for a structured verdict (e.g. JSON `{is_phishing: true, reason: "..."}`).
- **OSINT collection on portals without an API** — drive vendor portals, social platforms, dark-web forums, advisory boards.
- **Credential validation** — replay a leaked credential safely against a saved profile, behind a residential IP, with the agent reporting "logged in" / "blocked".
- **Evidence collection** — recordings + step-by-step messages + screenshots, attached to the incident.
- **Long-running automations** — keep a session alive and dispatch follow-up tasks against the same browser state.

## Pack contents

### Integration: **Browser Use**

| Resource | Commands |
| --- | --- |
| Account | `browser-use-account-info` |
| Agent tasks | `browser-use-task-run`, `browser-use-task-get`, `browser-use-task-list`, `browser-use-task-stop`, `browser-use-task-messages-list`, `browser-use-task-screenshot-get` |
| Stealth browsers (CDP) | `browser-use-browser-create`, `browser-use-browser-get`, `browser-use-browser-list`, `browser-use-browser-stop` |
| Profiles (persistent state) | `browser-use-profile-list`, `browser-use-profile-get`, `browser-use-profile-create`, `browser-use-profile-delete` |
| Workspaces (file storage) | `browser-use-workspace-list`, `browser-use-workspace-get`, `browser-use-workspace-create`, `browser-use-workspace-delete`, `browser-use-workspace-files-list` |

`browser-use-task-run` supports `wait=true` to block until the agent reaches a terminal state (`stopped`, `timed_out`, `error`), so it can be used directly in synchronous playbook flows.

### Integration: **Browser Use Local**

| Resource | Commands |
| --- | --- |
| Agent (open-source) | `browser-use-local-agent-run` |
| Quick screenshot (no LLM) | `browser-use-local-screenshot` |
| Diagnostics | `browser-use-local-version` |

Runs on a custom `demisto/browser-use:*` Docker image (Playwright + Chromium + open-source `browser-use` + LLM SDKs). A reference [`Dockerfile`](Integrations/BrowserUseLocal/Dockerfile) is included in the integration directory.

## Configuration

Generate an API key in the [Browser Use dashboard](https://cloud.browser-use.com/settings?tab=api-keys&new=1). The key starts with `bu_`.

The integration only needs:

- **Server URL** — defaults to `https://api.browser-use.com`
- **API Key** — `bu_...`

Defaults that you can override per-command (model, max cost cap, proxy country, session timeout, polling) are exposed as instance parameters under the **Defaults** section.

## References

- Product: <https://browser-use.com>
- Docs: <https://docs.browser-use.com>
- API reference: <https://docs.browser-use.com/cloud/api-reference>
- OpenAPI v3 spec: <https://docs.browser-use.com/cloud/openapi/v3.json>
