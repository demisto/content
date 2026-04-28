## Browser Use Local — open-source agent

This integration runs the **open-source** [`browser-use`](https://github.com/browser-use/browser-use) library. Chromium and the LLM client both execute **inside the integration container** — nothing leaves your environment except (optionally) the LLM API call.

It is intentionally a smaller surface than the **Browser Use** (cloud) integration in the same pack — three commands plus `test-module` — because every invocation is heavyweight (it spawns Chromium and burns LLM tokens).

### When to pick this integration

Use this integration when you need any of:
- **Air-gapped / on-prem** browser automation (no traffic to the Browser Use Cloud).
- A **specific LLM provider** (Anthropic / Google / OpenAI) using your own API key.
- Custom tools or full code control over the agent loop.

For high-throughput, stealth, residential proxies, recordings, and managed scaling, prefer the **Browser Use** (cloud) integration in this same pack.

### Docker image

The integration requires the `demisto/browser-use:*` image, which ships:
- Python 3.12 + Playwright + Chromium (with `--with-deps`)
- `browser-use` (pinned)
- LLM SDKs: `anthropic`, `google-generativeai`, `openai`

A reference `Dockerfile` is included in the integration directory and should be contributed upstream to [`demisto/dockerfiles`](https://github.com/demisto/dockerfiles).

### Configuration

| Setting | Notes |
| --- | --- |
| **LLM Provider** | One of `browser-use`, `anthropic`, `google`, `openai`. |
| **LLM API Key** | Provider-specific key. Required for any provider other than `browser-use` (the latter can pick up `BROWSER_USE_API_KEY` from the container environment). |
| **Default model** | Override the provider default. |
| **Default headless mode** | Stay `true` — the integration container has no display. |
| **Default max steps** | Hard cap on agent reasoning steps. |
| **Use Browser Use Cloud stealth browser** | Hybrid mode: open-source Agent here, but the browser runs on Browser Use Cloud (residential proxy + stealth). Requires a Browser Use Cloud key. |
| **Browser Use Cloud API Key** | Only for the hybrid mode above. |

### Validate

After saving, click **Test**. The check imports `browser_use` and instantiates the chosen LLM client. It does **not** actually call the LLM or launch Chromium.

### Cost note

Each `browser-use-local-agent-run` call spawns Chromium for the duration of the task. Consider lowering **Default max steps** when piloting and use the per-command `max_steps` argument to cap individual playbooks.
