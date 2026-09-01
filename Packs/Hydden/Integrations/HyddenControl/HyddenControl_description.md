
![Logo](./../../doc_files/icon.png)
## Hydden Control

Configure an instance with your Hydden Control API URL and API credentials.

The API user must be able to call the public REST API (`rest_api`). Enter your **Client ID** and **Client Secret**.

### Instance URL

Set **Hydden API URL** to the public API root: https://control.hydden.ai/api/public/v1

### Commands

- `hydden-blast-radius` — blast radius information string for an account (`GET /blast-radius?account_id=`). Output: `Hydden.Identity.blast_radius`.
- `hydden-deprovision-account` — deprovision the account (`POST /account-actions/deprovision?account_id=`). Marked potentially harmful. Output: `Hydden.Identity.deprovisioned`.