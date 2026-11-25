DarkEye searches a domain in two products, each with its own optional API key:

- **HaveIBeenRansom**: ransomware leaks and data breaches.
- **Breach House**: ransomware, breach, lead and stealer listings.

The pack has one integration, DarkEye, with the `darkeye-domain-search` command. It returns one `DarkEye.Domain` context entry per domain, and every record carries its product and category. Use it to check whether an organization, a vendor or a domain in an incident appears in ransomware leaks, breaches or stealer listings.

A record means the domain appears in a listing, usually as a victim. It does not mean the domain is malicious, so the integration sets no DBot score. Only listing metadata is returned (title, website, group, country, discovery date); leaked content, leak-site URLs and download links are not.
