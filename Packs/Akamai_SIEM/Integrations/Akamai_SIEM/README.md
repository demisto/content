# Get security event from [Akamai Web Application Firewall (WAF)](https://www.akamai.com/us/en/resources/waf.jsp) service.

This integration was integrated and tested with [API version 1.0 of Akamai WAF SIEM](https://developer.akamai.com/api/cloud_security/siem/v1.html).

## Use Cases
- Get security events from Akamai WAF.
- Analyze security events generated on the Akamai platform and correlate them with security events generated from other sources in Cortex XSOAR.

## Detailed Description
A WAF (web application firewall) is a filter that protects against HTTP application attacks. It inspects HTTP traffic before it reaches your application and protects your server by filtering out threats that could damage your site functionality or compromise data.

## API keys generating steps
1. Go to `WEB & DATA CENTER SECURITY` > `Security Configuration` > choose your configuration > `Advanced settings` > Enable SIEM integration.
2. [Open Control panel](https://control.akamai.com/) and login with admin account.
3. Open `identity and access management` menu.
4. Create a user with assigned roles `Manage SIEM` or make sure the admin has rights to manage SIEM.
5. Log in to the new account you created in the last step.
6. Open `identity and access management` menu.
7. Create `new api client for me`.
8. Assign an API key to the relevant user group, and on the next page assign `Read/Write` access for `SIEM`.
9. Save configuration and go to the API detail you created.
10. Press `new credentials` and download or copy it.
11. Now use the credentials to configure Akamai WAF in Cortex XSOAR.

## Configure Akamai WAF SIEM on Cortex XSOAR
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Akamai WAF SIEM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** | |
    | --- | --- | --- |
    | Server URL (e.g., https://example.net) | True | |
    | Client token | False | |
    | Access token | False | |
    | Client secret | False | |
    | Config ids to fetch | True | |
    | Incident type | False | |
    | First fetch timestamp | False | |
    | Fetch limit | False | Limit on the number of incidents retrieved in a single fetch. |
    | Page size | False | The number of events to fetch per request - the maximum is 600k, raise this parameter in case you're getting aggregated delays. |
    | Trust any certificate (not secure) | False | |
    | Use system proxy settings | False | |

4. Click **Test** to validate the new instance.

## Fetch Incidents
```json
[
    {
        "name": "Akamai SIEM: 50170",
        "occurred": "2019-12-10T18:28:27Z",
        "rawJSON": {
            "type": "akamai_siem",
            "format": "json",
            "version": "1.0",
            "attackData": {
                "configId": "50170",
                ...
            }
        }
    },
    {
        "name": "Akamai SIEM: 50170",
        "occurred": "2019-12-10T18:28:26Z",
        "rawJSON": {
            "type": "akamai_siem",
            "format": "json",
            "version": "1.0",
            "attackData": {
                "configId": "50170",
                ...
            }
        }
    }
]
```

### akamai-siem-reset-offset

***
Reset the last offset in case the offset is invalid.

#### Base Command

`akamai-siem-reset-offset`
