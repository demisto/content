## URLhaus
---

Fetch indicators from URLhaus api.


1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for Okta event collector.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter**             | **Description** | **Required** |
|---------------------------| --- |--------------|
| url                       | Okta URL (https://yourdomain.okta.com) | True         |
| events_to_add_per_request | XSIAM update limit per request | False        |
| limit                     | Api request limit | True         |
| proxy                     | Use system proxy settings | False        |
| method                    | HTTP Method | True         |
| headers                   | Headers | True         |
| encrypted_headers         | Encrypted headers | True         |


4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands in a playbook.
#### test-module
***
Integration command for testing.

#### fetch-events
***
Command that is activated by the engine to fetch event.

####$ okta-get-events
***
Manual command to fetch events and display them.