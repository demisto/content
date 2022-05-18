There are 2 list types, each list type holds the names of the miners(lists) that are accounted as threat intel lists (block list, allow list)
Each list type represents different DbotScore on Demisto.
Block list - if indicator is found in one of the block lists then the indicator will get DbotScore  3, which is considered malicious in Demisto.
Allow list - if indicator is found in one of the allow lists then the indicator will get DbotScore 1 which is considered good in Demisto.
If indicator is not found in any list, it will get DbotScore of 0 - unknown severity.