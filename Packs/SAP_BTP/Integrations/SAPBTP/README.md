# SAP BTP (Business Technology Platform)

## Overview

SAP Business Technology Platform is a cloud-based platform that enables organizations to build, integrate, and extend applications using data, analytics, AI, and automation tools. It combines database, development, and integration services into a unified environment optimized for enterprise business processes.

This integration collects audit log events from SAP BTP for security monitoring and compliance purposes in Cortex XSIAM.

## Authentication

This integration supports two authentication methods for connecting to the SAP BTP Audit Log API:

### mTLS (Mutual TLS) - Recommended

Mutual TLS provides the highest level of security by using client certificates for authentication. This method:

- Uses X.509 certificates for mutual authentication between the client and server
- Eliminates the need to manage and rotate client secrets
- Provides stronger security through certificate-based authentication
- Requires a certificate and private key pair generated from your SAP BTP service instance

**When to use**: Recommended for production environments and when enhanced security is required.

### Non-mTLS (Client Credentials)

This method uses OAuth 2.0 client credentials flow with a client ID and client secret:

- Simpler to set up initially
- Uses client ID and client secret for authentication
- Requires regular secret rotation according to security policies
- Suitable for development and testing environments

**When to use**: Suitable for development, testing, or when certificate-based authentication is not feasible.

## Before You Start

Before configuring the integration, you must complete the following prerequisites in your SAP BTP environment:

1. **Follow the prerequisites** described in the [SAP BTP Audit Log Retrieval API documentation](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#prerequisites).

2. **Create an instance of the auditlog-management service** as described in the [SAP BTP documentation](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#create-instance-of-the-auditlog-management-service).

3. **Generate authentication credentials**:
   - For **mTLS** (recommended): Obtain the certificate and private key files
   - For **Non-mTLS**: Obtain the Client ID and Client Secret

## Configure SAP BTP (Business Technology Platform) in Cortex XSIAM

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SAP BTP (Business Technology Platform).
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Service Key URL for your SAP BTP instance.<br/>Example: `https://auditlog-management.cfapps.us10.hana.ondemand.com` | True |
| Client ID | The OAuth2 Client ID (Username).<br/>Required for both mTLS and Non-mTLS authentication. | True |
| Authentication Type | Select the authentication method:<br/>- **mTLS** (recommended): Uses client certificates<br/>- **Non-mTLS**: Uses client credentials | True |
| Certificate | The body of the certificate.pem file.<br/>Required only when using mTLS authentication. | False |
| Private Key | The body of the key.pem file.<br/>Required only when using mTLS authentication. | False |
| Client Secret | The OAuth2 Client Secret (Password).<br/>Required only when using Non-mTLS authentication. | False |
| Trust any certificate (not secure) | When selected, the integration will not verify SSL certificates. | False |
| Use system proxy settings | When selected, the integration will use the system proxy settings. | False |
| Fetch events | Enable automatic collection of audit log events. | False |
| First fetch time | Time range to start fetching events from on first run.<br/>Default: 3 days<br/>Examples: "3 days", "1 week", "2024-01-01" | False |
| The maximum number of audit logs per fetch | Maximum number of events to fetch per collection cycle.<br/>Default: 5000<br/>Note: The API returns a maximum of 500 events per page. | False |

4. Click **Test** to validate the connection and authentication.
5. Click **Done** to save the integration instance.

## How It Works

This integration automatically collects audit log events from SAP BTP and sends them to Cortex XSIAM for security monitoring and compliance.

1. **Initial Collection**: On the first run, the integration begins collecting events from the configured start time (default: 3 days ago).
2. **Continuous Monitoring**: The integration automatically tracks the last collected event and fetches only new events on subsequent runs.
3. **Automatic Pagination**: The integration handles large result sets automatically, retrieving up to the configured maximum number of events per collection cycle.

## Additional Resources

For more information about SAP BTP Audit Logging, refer to the official SAP documentation:

- [Audit Log Retrieval API Prerequisites](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#prerequisites)
- [Create OAuth Access Token](https://help.sap.com/docs/btp/sap-business-technology-platform/audit-log-retrieval-api-for-global-accounts-in-cloud-foundry-environment#create-an-oauth-access-token)
- [Rate Limiting Rules](https://help.sap.com/docs/btp/sap-business-technology-platform/rate-limiting-rules)

## Best Practices

1. **Use mTLS Authentication**: For production environments, always use mTLS authentication with client certificates for enhanced security.
2. **Configure Appropriate Limits**: Set the maximum number of events per fetch based on your organization's event volume.
3. **Secure Credential Storage**: Ensure that authentication credentials (certificates or secrets) are stored securely and rotated regularly according to your organization's security policies.
