# Browser Use

[Browser Use](https://browser-use.com) is a managed AI browser automation platform: send a natural-language instruction and an LLM agent (Claude Opus / Sonnet, Gemini 3 Flash) drives a stealth Chromium browser to do the work — with residential proxies in 195+ countries, CAPTCHA solving, recordings, and persistent profiles.

This pack adds a Cortex XSOAR / XSIAM integration that wraps the Browser Use Cloud API (v3).

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
