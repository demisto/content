## Browser Use Cloud (v3) — Setup

[Browser Use](https://browser-use.com) is a managed AI browser automation service. You give the agent a natural-language task and it drives a stealth Chromium browser to complete it (with residential proxies, CAPTCHA solving, recordings, and persistent profiles).

### Get an API key

1. Sign in to the [Browser Use Cloud Dashboard](https://cloud.browser-use.com).
2. Open **Settings → API Keys** ([direct link](https://cloud.browser-use.com/settings?tab=api-keys&new=1)).
3. Click **Create API Key**. The key starts with `bu_`. Copy it now — you cannot retrieve it later.

### Configure the integration

| Setting | Notes |
| --- | --- |
| **Server URL** | Leave as `https://api.browser-use.com` unless instructed otherwise. The `/v3` API version is appended automatically. |
| **API Key** | The `bu_...` key generated above. Stored encrypted. |
| **Default model** | Default LLM tier for `browser-use-task-run`. `bu-mini`/`gemini-3-flash` is fastest & cheapest, `claude-sonnet-4.6` is balanced (recommended), `claude-opus-4.6` is most capable. |
| **Default max cost per task (USD)** | Safety cap per agent task. Set to a low number (e.g. `0.25`) when piloting. |
| **Default proxy country** | Two-letter ISO country code for the residential proxy. Empty disables proxy. |
| **Default session timeout** | Minutes (1–240). |
| **Wait-for-completion timeout / Polling interval** | Used when `wait=true` is passed to `browser-use-task-run`. |

### Validate

After saving, click **Test**. It calls `GET /v3/billing/account`. A valid `bu_` key returns `ok`. An invalid key returns an authorization error.

### Cost & rate limits

All commands hit your Browser Use account quota. Use **`!browser-use-account-info`** at any time to inspect remaining credits.
