## IsMalicious

### Get API credentials

1. Sign in to [your IsMalicious account](https://ismalicious.com/app/account), or create an account first.
2. Generate an API key and API secret in the account settings.
3. Base64-encode the exact `apiKey:apiSecret` pair. The raw API key alone is insufficient.
4. Store the complete encoded credential in the integration's **X-API-KEY credential** password field. Keep this value secret.

### Configure the integration instance

API checks require REST access and consume the account's applicable request quota. TAXII feed access is separate. Enable **Use system proxy settings** only if requests should use the proxy configured in Cortex. TLS verification is mandatory; redirects and automatic retries are disabled.

Select **Source Reliability** using your team's assessment of the provider, independently of indicator risk and confidence. The default is F (cannot be judged).

### Test connection and troubleshoot

**Test** checks `example.com` to validate authentication, not indicator safety. For HTTP 401 or 403, verify the complete credential and API permissions. For HTTP 429, check the account's quota and rate limits. An error or an unknown response does not produce a benign verdict.
