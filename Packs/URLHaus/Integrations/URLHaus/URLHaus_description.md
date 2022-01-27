## How DBot Score is Calculated

### DBot Score: Bad
URL: receive a DBot score of Bad if their status is online.

Domain: receive a DBot score of Bad if their status in the blacklist is:
    spammer_domain/phishing_domain/botnet_cc_domain/listed
### DBot Score: Suspicious
URL: receive a DBot score of Suspicious if their status is offline.

Domain: There is no such an option.
### DBot Score: Good
URL: receive a DBot score of Good If there is no information about url status.

Domain: receive a DBot score of Good If there is no information about domain blacklist.
### DBot Score: Empty
URL: will not receive a DBot score if their status is unknown.

If there is no information for the URLs and domains, they will not receive a DBot score.
