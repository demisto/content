## How DBot Score is Calculated

### URL

Determined by the status of the URL.

| **Status** | **DBotScore** |
| --- | --- |
| online | Malicious |
| offline | Suspicious |
| offline | Suspicious |
| unknown | Unknown |

### Domain

Determined by the blacklist spamhaus_dbl/surbl of the Domain.

| **Status**                                                | **DBotScore** |
|-----------------------------------------------------------| --- |
| spammer_domain/ phishing_domain/ botnet_cc_domain/ listed | Malicious |
| not listed                                                | Unknown |
| -                                                         | Benign |
| unknown                                                   | Unknown |

### File

Score is Malicious.

| **Status** | **DBotScore** |
|---| --- |
| - | Malicious |