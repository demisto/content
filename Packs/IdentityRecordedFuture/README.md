# Recorded Future Identity Pack

## Overview

The Recorded Future Identity Pack for Cortex XSOAR provides enhanced threat intelligence capabilities focused on
identity-related exposures. This pack integrates Recorded Future's rich data to automate the detection, investigation,
and response to identity threats. The pack includes new playbooks, incident types, layouts, and classifiers to
streamline identity threat management and response workflows.

## What Does This Pack Do?

### Integrations

- **Recorded Future Identity**: Integrates with Recorded Future to search and look up identity-related data.
- **Recorded Future Identity - Playbook Alerts**: Allows importing Recorded Future Playbook Alerts specifically for
  Identity Novel Exposures into XSOAR incidents.

### Commands

- **recordedfuture-identity-search**: Searches for identity-related data.
- **recordedfuture-identity-lookup**: Looks up detailed information about identities.
- **recordedfuture-identity-playbook-alerts-details**: Fetches Playbook alert details by ID.
- **recordedfuture-identity-playbook-alerts-update**: Updates the status of one or multiple Playbook alerts.
- **recordedfuture-identity-playbook-alerts-search**: Searches Playbook alerts based on filters.

### Classifiers

- **Recorded Future Identity - Incoming Mapper**: Parses incidents fetched by the Recorded Future Identity - Playbook
  Alerts integration to ensure correct data handling and response initiation.

### Incident Types

- **Recorded Future Identity Exposure**: New incident type tailored for incidents fetched by the Recorded Future
  Identity - Playbook Alerts integration.
- **Recorded Future Identity (Deprecated)**: The previous incident type has been deprecated in favor of the new, more
  specialized incident type.

### Incident Fields

- New fields to enhance the data captured and utilized in identity-related incidents:
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

- **Recorded Future Playbook Alert Identity Exposure**: A new layout designed for the Recorded Future Identity Exposure
  incident type to provide a clear and organized view of relevant information.
- **Deprecated: Recorded Future Identity Incident**: The previous layout has been deprecated in favor of the new layout.

### Playbooks

- **Recorded Future - Identity Exposure**: A comprehensive playbook developed as a template response when an Identity
  Exposure Playbook Alert is triggered.
- Deprecated Playbooks:
    - Recorded Future Workforce Usecase
    - Recorded Future External Usecase
    - Recorded Future Identity - Lookup Identities (parent)
    - Recorded Future Identity - Create Incident (sub)
    - Recorded Future Identity - Identity Found (incident)

## Installation

To install the Recorded Future Identity Pack, follow these steps:

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **Recorded Future Identity** and **Recorded Future Identity - Playbook Alerts**.
3. Click **Add instance** to create and configure new integration instances.

For detailed configuration instructions, refer to:

- the [Recorded Future Identity Integration Documentation](https://github.com/demisto/content/blob/master/Packs/IdentityRecordedFuture/Integrations/IdentityRecordedFuture/README.md)
- the [Recorded Future Identity - Playbook Alerts Integration Documentation](https://github.com/demisto/content/blob/master/Packs/IdentityRecordedFuture/Integrations/IdentityRecordedFuturePlaybookAlerts/README.md)

## Dependencies

This pack depends on the following content packs:

- **Core Alert Fields** (mandatory)
- **Common Types** (mandatory)
- **Filters And Transformers** (mandatory)
- **Common Scripts** (mandatory)
- **PAN-OS by Palo Alto Networks**
- **Okta**
- **Malware Core**
- **Active Directory Query**