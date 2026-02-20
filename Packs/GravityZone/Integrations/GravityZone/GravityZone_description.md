## GravityZone Integration

For detailed API documentation, refer to the [Bitdefender GravityZone Public API](https://www.bitdefender.com/business/support/en/77209-125277-public-api.html).

GravityZone provides secure API access to incident and event data, as well as the ability to perform remediation actions.

To integrate with third-party applications, you must generate an API Key, which authorizes communication with the GravityZone Cloud platform.

### API Key Management

API Keys are created in the My Account section of the GravityZone Control Center. Each key grants access to selected APIs, as specified during creation.

Some sensitive operations require elevated permissions. If required, contact Bitdefender Enterprise Support to have your API key permissions updated.

#### Generating an API Key

To generate an API Key:

1. Log in with an administrator account that has the View and Analyze Data, Manage Networks, Manage Users and Manage Company permissions. 
2. Click your username in the upper-right corner and select **My account**.
3. Go to the **API keys** section and click **Add**.
4. Provide a description and select the APIs to enable.
5. Click **Generate**.
6. The API Key will be displayed. It is only visible while this window is open and cannot be retrieved later.
7. Use the **Copy & Paste** button to copy and securely store the key.
8. Close the window. The new key will appear in the API Keys section in an obfuscated format, along with its details.

#### Security Notice

API Keys provide access to sensitive data, including packages and inventory. Do not share your API Keys to prevent unauthorized access.

#### Mirroring

When enabled, mirroring applies only to the Incident status field.
- Closing an incident in Cortex XSOAR closes the corresponding incident in GravityZone and adds a related note.
- Closing an incident in GravityZone also closes the corresponding incident in Cortex XSOAR.
- To reopen an incident in Cortex XSOAR and trigger synchronization, you must change the status and at least one additional field.
- Reopening an incident in GravityZone is not currently synchronized to Cortex XSOAR.