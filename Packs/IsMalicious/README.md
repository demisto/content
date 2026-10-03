# IsMalicious

Enrich IP addresses, fully qualified domains, full HTTP(S) URLs and MD5/SHA1/SHA256 hashes during an investigation. This community pack uses IsMalicious REST indicator checks and returns standard indicator reputation plus the original provider evidence.

## Authentication

Create an API key and API secret in [your IsMalicious account](https://ismalicious.com/app/account). Store Base64 of the exact `apiKey:apiSecret` pair in the integration's **X-API-KEY credential** password field. The raw API key alone is insufficient. Keep this complete credential secret. Each check consumes the account's applicable REST request quota; this pack does not collect a TAXII feed.

TLS verification is mandatory. A system proxy is optional. Requests have a 25-second timeout, no automatic retries, and no redirects. HTTP errors, rate limits, timeouts and invalid responses fail explicitly and do not produce a benign verdict.

## Commands and evidence

The standard `ip`, `domain`, `url` and `file` commands accept at most 50 indicators per call. The `file` command looks up hashes only and never uploads file contents. Each command validates all argument types before making a request. IPs, domains and hashes can be comma-separated or arrays; a URL string is one complete URL, including any commas. Pass multiple URLs as an array. URLs containing user information or passwords are rejected before any request.

`IsMalicious.Check` includes the provider's evidence, risk score, separate nullable confidence, explicit blocklist hit count, source context, data-trust profile, hash lookup state, known-good/delisted flags and report link. Source context may include infrastructure, policy or allowlist information, so its row count must not be treated as a detection count.

DBotScore is 0 for unknown or delisted results, 1 only for explicit clean/benign server evidence, 2 for suspicious evidence and 3 for malicious evidence. A legacy response without evidence supports malicious=true as 3; malicious=false stays 0. A zero risk score or an empty detection list is not a clean verdict. Hash lookupStatus=unknown always remains unknown. Review evidence reasons, contradictions and data freshness before any containment decision.

This pack does not fetch incidents, automatically block indicators or claim attribution that the API has not returned. Reliability defaults to F (cannot be judged), and can be assessed by your team independently of risk and confidence.

## Validation and deployment

Unit tests exercise the real CommonServerPython client with synthetic responses. They cover evidence mapping, unknown hashes, delisting, exact query encoding, URL commas, command type checks, batch limits, 302/401/403/429/500 errors, timeouts and standard indicator context. A successful synthetic test is not a production lookup or a deployed XSOAR instance. Validate configuration and permissions in a staging XSOAR instance before enabling analyst workflows.
