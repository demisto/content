To use Digital Guardian External API calls, you must first get a valid token to use for authentication.

### Getting a new Token
You must obtain the following values by filing a request via the Digital Guardian Support Portal:

| **Requested Information** | **Mapped to Integration Field Name** |
| --- | --- |
| API Client ID | client_id |
| API Client Secret | client_secret |
| Gateway Base URL | arc_url |
| Auth Server URL | auth_url |

Note:
The export_profile for use with this integration has the ID of 'demisto'.  This Export Profile requires ARC 2.12.0 in order to function properly.

