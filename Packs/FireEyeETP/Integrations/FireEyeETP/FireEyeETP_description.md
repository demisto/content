Trellix Email Security - Cloud is a cloud-based platform that protects against advanced email attacks.

To use this integration, you must enter the correct instance URL and the corresponding credentials in the instance parameters.

---
Authentication Configuration
---

To ensure a successful connection, you must select the correct authentication method based on the Base URL (Instance URL) you are configuring. We support two different authentication methods depending on the endpoint domain:

| Domain Used in Server URL | Authentication Method | Required Parameters |
|:------------------------|:----------------------|:--------------------|
| Ends in trellix.com     | OAuth 2.0             | Client ID, Client Secret, and OAuth Scopes |
| Ends in fireeye.com     | Legacy API Key        | API Key (only) |

For official documentation on configuring access, [see here.](https://docs.trellix.com/bundle/etp_api/page/UUID-30726aa3-e420-6f62-6b84-6ad0bdace483.html)