## KELA Monitor

Fetches the incidents of your KELA Monitor into Cortex and lets you list them by incident type. KELA Monitor is the successor of KELA RaDark: if a KELA RaDark instance fetches the same monitor, disable it first, otherwise every incident is created twice.

### Configuration steps

1. **API Token**: use a dedicated KELA platform user for the integration. The token is per user and can be rotated. Generate it in the KELA platform under **Settings** (bottom-left) > **API access** (also available from the user menu as **Generate API Key**). It is sent in the `apiToken` HTTP header, not in the URL, and the integration masks it in its logs and error messages.
2. **Monitor ID**: open your Monitor in the KELA platform and copy the `monitorId` value from the page URL. One instance connects to one Monitor.
3. Select **Fetch incidents** and leave **Incident type** empty: the KELA Monitor classifier and incoming mapper set one incident type per KELA incident type and fill the KELA Monitor incident fields.
4. **Incident types to fetch** (required when **Fetch incidents** is selected): choose the types your Monitor license includes. `botnets` is the Compromised Accounts type of the KELA platform. Intelligence Report and Data-Loss Detection are not fetched. Each type is fetched with its own position, so adding a type later does not fetch the others again.
5. Set **First fetch time** (default 3 days) and **Maximum number of incidents per fetch** (default 50 per incident type).
6. Click **Test**, then **Save & exit**. The first incidents appear after the first fetch cycle; a large first-fetch backlog is created over several cycles, oldest first.

### Connection options

- **Server URL** must use https.
- **Trust any certificate (not secure)**: skips the TLS certificate check. Use it only for testing.
- **Use system proxy settings**: sends the requests through the proxy configured on the server or engine.

### Good to know

- If the token has no access (403) to some of the selected incident types, those are skipped and the others keep working, but **Test** reports the forbidden types instead of a success. If it has no access to any of them, the fetch fails with a clear message.
- Sensitive data (passwords, cookies, tokens, secrets, card numbers, and the email or user name in incident names) is masked by default. It can be disabled with **Mask sensitive data**; the masked incident fields stay masked either way.
- **Do not create incidents already handled in KELA** skips incidents a user already marked as handled in the KELA platform.
- Hacking discussions are fetched as a snippet only, not the full text. Hidden and deleted incidents are not created in Cortex.
- The KELA API allows 1 request per second; requests answered with 429 are retried with a growing delay, so a cycle that reads a large backlog can take a few minutes.
- The integration is read-only: it does not change anything in KELA.
