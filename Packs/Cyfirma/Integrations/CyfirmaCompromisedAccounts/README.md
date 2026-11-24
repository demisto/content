# CYFIRMA Compromised Accounts
 
CYFIRMA is an AI-powered Preemptive External Threat Landscape Management platform that enables organizations to predict, identify, and prevent cyber threats by gaining visibility into external exposure and adversary intent. By transforming threat intelligence into predictive insights and actionable risk intelligence, CYFIRMA helps organizations reduce cyber risk, protect critical digital assets, and move from reactive defence to proactive threat prevention.
 
This integration fetches compromised account alerts from CYFIRMA and creates incidents in Cortex XSOAR / Cortex XSIAM, so security teams can investigate and respond to leaked or stolen credentials.
 
This integration was integrated and tested with the CYFIRMA API.
 
## Prerequisites
 
- A CYFIRMA account with access to the Compromised Accounts API.
- A valid CYFIRMA API key.
- Network access from the Cortex engine or server to the CYFIRMA API URL (default: `https://api.cyfirma.com`).
## Configure CYFIRMA Compromised Accounts in Cortex
 
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API URL (e.g. https://api.cyfirma.com) | The base URL of the CYFIRMA API. Default: `https://api.cyfirma.com`. | True |
| API Key | The API key used to authenticate with CYFIRMA. | True |
| Use system proxy settings | Use the system proxy settings for requests to the CYFIRMA API. | False |
| Trust any certificate (not secure) | Skip SSL certificate verification. Not recommended for production use. | False |
| Fetch incidents | Enable fetching of compromised account alerts as incidents. | False |
| Include third party Compromised Accounts | Also fetch compromised accounts that belong to third parties. | False |
| Incidents Fetch Interval | Interval, in minutes/hours/days, between incident fetches. Default: 5. | False |
| How much time before the first fetch to retrieve incidents | How far back to look on the first fetch. Options: 15, 30, 60, 90, 120, 160, or 180 days. Default: 60 days. | False |
| Maximum number of incidents per fetch | The maximum number of incidents to create in each fetch cycle. Default: 100. | False |

## Fetch Incidents
 
When **Fetch incidents** is enabled, the integration periodically retrieves compromised account alerts from CYFIRMA and creates an incident for each one.
 
- On the first run, the integration retrieves alerts going back by the period set in **How much time before the first fetch to retrieve incidents** (default: 60 days).
- On subsequent runs, only new alerts since the last fetch are retrieved.
- Each fetch creates at most the number of incidents set in **Maximum number of incidents per fetch** (default: 100).
- Enable **Include third party Compromised Accounts** to also include compromised accounts related to third parties.
- Set **Incident type** to classify the created incidents.
## Commands
 
This integration does not provide any commands. It is used only for fetching incidents.
 
## Troubleshooting
 
- **Authorization or connection errors on Test:** Verify that the API URL is correct and that the API key is valid and active.
- **SSL errors:** Ensure the certificate chain is trusted. Use **Trust any certificate (not secure)** only for troubleshooting.
- **No incidents created:** Confirm that **Fetch incidents** is enabled, that an **Incident type** is selected, and that the first fetch period covers the time range of the alerts you expect.
- **Proxy issues:** If your environment requires a proxy, enable **Use system proxy settings**.
 