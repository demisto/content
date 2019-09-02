## How DBot Score is Calculated

A URL or domain can have one of the following statuses in a blacklist.
- Malicious: the site is a known malware site.
- Compromised: the site is legitimate but has been compromised.
- Not listed

If the `compromised_is_malicious` parameter is set to True, then compromised URLs or domains are treated as malicious.

If the `compromised_is_malicious` parameter is set to False, then compromised URLs or domains are treated as legitimate.

### DBot Score: Bad
URLs and domains receive a DBot score of Bad if their total number of appearances in blacklists exceeds the `threshold` parameter.

### DBot Score: Suspicious
URLs and domains receive a DBot score of Suspicious if they appear on at least on blacklist, but their total number of appearances in blacklists does not exceed the `threshold` parameter.
If the URL or domain appeared in at least one blacklist, but not enough blacklists to exceed the threshold, it is considered suspicious.

### DBot Score: Good
URLs and domains receive a DBot score of Good if they do not appear on any blacklists.their total number of appearances in blacklists exceeds the `threshold` parameter.

### DBot Score: Empty
If there is no information for the URLs and domains, they will not receive a DBot score.
