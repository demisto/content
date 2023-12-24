## Email Hippo
- You can obtain your MORE API key by signing in to the [Email Hippo portal](https://app.emailhippo.com/).
  - MORE API Key: MORE -> API Keys.
  - WHOIS API Key: WHOIS -> API Keys.

### Limitation
- Allowed throughput is 220 MORE email validation requests per second. Throughput exceeding these limits will receive HTTP response code 429 (too many requests) for subsequent requests for a duration of one minute.
- There is a quota for both MORE and WHOIS:
  - MORE - 100 Free Trial for 1 month.
  - WHOIS - 15 Free Trial for 1 month.

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/email-hippo)