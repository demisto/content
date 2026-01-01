# Analyst1 Integration Configuration

This integration connects XSOAR to the Analyst1 threat intelligence platform to enrich indicators and manage sensor taskings.

## Configuration Parameters

### Server Configuration
- **Domain of Analyst1 server**: Enter your Analyst1 server domain in the format `server.analyst1.com`
  - Do not include `http://` or `https://`
  - Example: `yourdomain.analyst1.com`

### API Credentials
- **Username and Password**: Provide the username and password for the Analyst1 account with the REST role assigned

### Risk Score Mapping (Optional)
The integration includes configurable risk score mapping parameters that control how Analyst1 risk scores map to XSOAR verdicts:
- **Lowest**: Default mapping is Benign
- **Low**: Default mapping is Unknown
- **Moderate**: Default mapping is Suspicious
- **High**: Default mapping is Suspicious
- **Critical**: Default mapping is Malicious
- **Unknown**: Default mapping is Unknown

These can be customized based on your organization's risk tolerance and threat response procedures.

### Entity Type Tags (Optional)
Enable "Apply Analyst1 entity-type tags to indicators" to automatically tag indicators with Analyst1 entity classifications such as:
- Analyst1: Indicator
- Analyst1: Asset
- Analyst1: In Private Range
- Analyst1: Ignored Indicator

## Support

For assistance with this integration, contact Analyst1 support:
- **Email**: support@analyst1.com
- **Documentation**: https://xsoar.pan.dev/docs/reference/integrations/analyst1
