1. Configure "Base server URL" as base url of your Deep Instinct environment. i.e https://my-deep-instinct-path.deepinstinctweb.com
2. Configure "API Key" as your api connector key from your Deep Instinct environment.
    a. In you Deep Instinct environment, go to "settings" > "api connectors".
    b. Create your own api connector with "full access" and click "copy"
    c. Paste the copied api key to "API Key" field in demisto
3. Configure "first_fetch_id" to be the first event id to start fetching from