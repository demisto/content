# What does this pack do?

- Enables users to fetch Indicators from ServiceNow platform into Cortex XSIAM TIM.
- Tag indicators that are added into the TIM.
- Query ServiceNow data with the ServiceNow query URL.

<~XSIAM>

### Supported Indicator Types

"""Type of Indicator (Reputations), used in TIP integrations"""

- Account = "Account"
- CVE = "CVE"
- Domain = "Domain"
- DomainGlob = "DomainGlob"
- Email = "Email"
- File = "File"
- FQDN = "Domain"
- MD5 = "File MD5"
- SHA1 = "File SHA-1"
- SHA256 = "File SHA-256"
- Host = "Host"
- IP = "IP"
- CIDR = "CIDR"
- IPv6 = "IPv6"
- IPv6CIDR = "IPv6CIDR"
- Registry = "Registry Key"
- SSDeep = "ssdeep"
- URL = "URL"

### Configure ServiceNow Generic Feed Indicator on XSIAM Tenant

1. Go to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for ServiceNow Generic Feed
3. Click **Add instance**.
4. Insert the ServiceNow URL.
5. Insert your credentials (user name and password).
6. Scroll down to the **Collect** section.
7. Mark **Fetch Indicators** and select the desired indicator type to fetch

</~XSIAM>
