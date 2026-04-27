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

#### Create an Auth Key for abuse.ch
> Note: If you already have a profile, you can skip steps 1 and 2.

1. Sign up for an abuse.ch account. You can do this easily by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
  
2. Once you are authenticated on abuse.ch, ensure that you connect at least one additional authentication provider. This will ensure that you have access to abuse.ch platforms, even if one of the authentication providers you use shuts down (yes, it happened with Twitter!)

3. Ensure that you hit the "Save profile" button. In the "Optional" section, you can now generate an "Auth-Key". This is your personal Auth-Key that you can now use in the integration.