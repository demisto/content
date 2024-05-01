## How DBot Score is Calculated

### URL

Determined by the status of the URL.

| **Status** | **DBotScore** |
| --- | --- |
| online | Malicious |
| offline | Suspicious |
| unknown | Unknown |

### Domain

Determined by the blacklist spamhaus_dbl/surbl of the Domain.

| **Status**                                                | **DBotScore** |
|-----------------------------------------------------------| --- |
| spammer_domain/ phishing_domain/ botnet_cc_domain/ listed | Malicious |
| not listed                                                | Unknown |
| In any other case                                                       | Benign |

### File

Score is Malicious.


Notice: Submitting indicators using the following commands of this integration might make the indicator data publicly available.
- ***url***
- ***domain***
See the vendor’s documentation for more details.
