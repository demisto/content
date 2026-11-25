## DarkEye

DarkEye searches a domain in two products, each with its own API key:

- **HaveIBeenRansom**: ransomware leaks and data breaches. Get the API token from your HaveIBeenRansom profile ([API documentation](https://haveibeenransom.com/howapi)).
- **Breach House**: ransomware, breach, lead and stealer listings. Get the API token from the Breach House customer panel ([API documentation](https://breach.house/docs)).

Both keys are optional, but at least one is required. A product without a key is skipped.

**Test** checks every configured key. For Breach House it calls the account endpoint; HaveIBeenRansom has no account endpoint, so it runs one domain search, which counts against the daily quota.

A record means the domain appears in a listing, usually as a victim. It does not mean the domain is malicious, so the integration sets no DBot score.