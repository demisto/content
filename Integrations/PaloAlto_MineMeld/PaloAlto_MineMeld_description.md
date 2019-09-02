There are 2 list types, each list type holds the names of the miners(lists) that are accounted as threat intel lists (blacklist, whitelist)
Each list type represents different DbotScore on Demisto.
Blacklist - if indicator is found in one of the blacklists then the indicator will get DbotScore  3, which is considered malicious in Demisto.
Whitelist - if indicator is found in one of the whitelists then the indicator will get DbotScore 1 which is considered good in Demisto.
If indicator is not found in any list, it will get DbotScore of 0 - unknown severity.