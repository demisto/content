## endoflife.ai

endoflife.ai is an independent service that publishes end-of-life and end-of-support dates, an EOL risk score and CISA Known Exploited Vulnerabilities (KEV) exposure for software and hardware products. Each date is labelled with its source.

### Get an API key

Every data request to the endoflife.ai API needs an API key. A free API key is available at [https://endoflife.ai/api#free-key](https://endoflife.ai/api#free-key). The key is sent to you by email.

### Configure the instance

1. Keep the default **Server URL**, `https://api.endoflife.ai`.
2. Paste the key into the **API Key** field.
3. Click **Test**. The test sends one request with the key and reports whether the API accepted it.

### Notes

- Each request counts against the daily request allowance of the API key. When the allowance is used up, commands return a rate limit message until the counter resets at 00:00 UTC.
- The ***endoflife-ai-version-batch-get*** command sends 5 product and version pairs per request by default, which is what a free API key accepts.
- The API documentation is at [https://endoflife.ai/api](https://endoflife.ai/api).
