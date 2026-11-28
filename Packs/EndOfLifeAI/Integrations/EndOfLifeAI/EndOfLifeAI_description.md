## endoflife.ai

### Get an API key

Every data request to the endoflife.ai API needs an API key.

1. Navigate to [https://endoflife.ai/api#free-key](https://endoflife.ai/api#free-key).
2. Enter your email address to request a free API key.
3. Check your email for the message containing the API key.

### Configure the instance

1. Keep the default **Server URL**, `https://api.endoflife.ai`.
2. Paste the key into the **API Key** field.
3. Click **Test**. The test sends one request with the key and reports whether the API accepted it.

### Notes

- Each request counts against the daily request allowance of the API key. When the allowance is used up, commands return a rate limit message until the counter resets at 00:00 UTC.
- The ***endoflife-ai-version-batch-get*** command sends 5 product and version pairs per request by default, which is what a free API key accepts.
- The API documentation is at [https://endoflife.ai/api](https://endoflife.ai/api).
