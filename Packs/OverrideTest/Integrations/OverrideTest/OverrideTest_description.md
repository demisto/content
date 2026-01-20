## CAPE Sandbox Integration Configuration

This integration allows you to interact with CAPE Sandbox for automated malware analysis.

### Authentication Methods

CAPE Sandbox supports two authentication methods:

#### 1. API Token Authentication (Recommended)

- **API Token**: Use the token generated in your CAPE Sandbox instance
- If provided, Username/Password authentication is not required

#### 2. Username and Password Authentication

- **Username**: Your CAPE Sandbox username
- **Password**: Your CAPE Sandbox password
- Used for token generation if API Token is not provided

### Configuration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| **Server URL** | Yes | Base URL of your CAPE Sandbox instance (e.g., `https://cape.example.com`) |
| **API Token** | No* | Token value as generated in CAPE. If provided, Username/Password is not required |
| **Username** | No* | Required if using Username/Password authentication |
| **Password** | No* | Required if using Username/Password authentication |
| **Trust any certificate** | No | Enable if using self-signed certificates (not recommended for production) |
| **Use system proxy settings** | No | Enable to use system proxy configuration |

*Either API Token OR Username/Password must be provided

### Important Notes

- **Authentication Priority**: If both API Token and Username/Password are provided, the API Token will be used
- **Polling Commands**: File and URL submission commands use polling to wait for analysis completion
- **Rate Limiting**: Be mindful of API rate limits when submitting multiple files or URLs

### Testing the Connection

After configuration, use the **Test** button in XSOAR/XSIAM to verify:

- Server URL is accessible
- Authentication credentials are valid
- API permissions are correctly configured

### Common Issues

**Connection Failed**

- Verify the Server URL is correct and accessible
- Check firewall rules allow outbound connections to CAPE Sandbox
- Ensure the CAPE Sandbox service is running

**Authentication Failed**

- Verify API Token is valid and not expired
- For Username/Password: ensure credentials are correct
- Check user has appropriate permissions in CAPE Sandbox

**SSL Certificate Errors**

- For self-signed certificates, enable "Trust any certificate" option
- For production, use valid SSL certificates

### Additional Resources

- [CAPE Sandbox Documentation](https://capev2.readthedocs.io/en/latest/)
- [CAPE Sandbox API Reference](https://capev2.readthedocs.io/en/latest/usage/api.html)
