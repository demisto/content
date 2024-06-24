# Recorded Future Identity Pack

## Overview

The Recorded Future Identity Pack for Cortex XSOAR provides enhanced threat intelligence capabilities focused on
identity-related exposures. This pack integrates Recorded Future's rich data to automate the detection, investigation,
and response to identity threats. The pack includes playbooks, incident types, layouts, and classifiers to streamline
identity threat management and response workflows.

## What Does This Pack Do?

### Integration

- **Recorded Future Identity**: Integrates with Recorded Future to provide comprehensive identity-related threat
  intelligence. This integration enables searching and looking up identity data, managing Playbook Alerts for Identity
  Novel Exposures, and streamlining incident response workflows.

### Commands

- **recordedfuture-identity-search**: Searches for identity-related data.
- **recordedfuture-identity-lookup**: Looks up detailed information about identities.
- **recordedfuture-password-lookup**: Looks up password information in the Recorded Future dataset.
- **recordedfuture-identity-playbook-alerts-details**: Fetches Playbook alert details by ID.
- **recordedfuture-identity-playbook-alerts-update**: Updates the status of one or multiple Playbook alerts.
- **recordedfuture-identity-playbook-alerts-search**: Searches Playbook alerts based on filters.

### Classifiers

- **Recorded Future Identity - Incoming Mapper**: Parses incidents fetched by the Recorded Future Identity integration
  to ensure correct data handling and response initiation.

### Incident Types

- **Recorded Future Identity Exposure**: Tailored for incidents fetched by the Recorded Future Identity integration.

### Incident Fields

- Fields to enhance the data captured and utilized in identity-related incidents:
    - Assessment
    - Authorization URL
    - Compromised Host
    - Dump Name
    - Exposed Hint
    - Exposed Properties
    - Exposed Secret
    - Exposed Value
    - Identity
    - Malware Family

### Layouts

- **Recorded Future Playbook Alert Identity Exposure**: Designed for the Recorded Future Identity Exposure incident type
  to provide a clear and organized view of relevant information.

### Playbooks

- **Recorded Future - Identity Exposure**: A comprehensive playbook developed as a template response when an Identity
  Exposure Playbook Alert is triggered.

### Deprecated Components

- **Incident Type**: Recorded Future Identity
- **Layouts**: Recorded Future Identity Incident
- **Playbooks**:
    - Recorded Future Workforce Usecase
    - Recorded Future External Usecase
    - Recorded Future Identity - Lookup Identities (parent)
    - Recorded Future Identity - Create Incident (sub)
    - Recorded Future Identity - Identity Found (incident)

## Setup Instructions

To set up the Recorded Future Identity integration in Cortex XSOAR, follow these steps:

1. **Navigate to Integrations**:
    - Go to **Settings** > **Integrations** > **Servers & Services**.

2. **Search for Recorded Future Identity**:
    - In the search bar, type **Recorded Future Identity**.

3. **Add a New Instance**:
    - Click **Add instance** to create and configure a new integration instance.

4. **Configure the Integration**:
    - Enter the required parameters such as Server URL and API Token.
    - Adjust optional settings like proxy usage and incident fetching as needed.

5. **Test the Configuration**:
    - Click **Test** to ensure the settings are correct and that the connection to Recorded Future is successful.

6. **Setup Pre-Process Rule**:
    - The configuration of the preprocessing rule is optional, but highly recommended.

For detailed configuration instructions, refer to
the [Recorded Future Identity Integration Documentation](https://github.com/demisto/content/blob/master/Packs/IdentityRecordedFuture/Integrations/IdentityRecordedFuture/README.md).

## Dependencies

This pack depends on the following content packs:

- **Common Types** (mandatory)
- **Filters And Transformers** (mandatory)
- **Common Scripts** (mandatory)
- **PAN-OS by Palo Alto Networks**
- **Okta**
- **Malware Core**
- **Active Directory Query**

---
