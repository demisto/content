# Recorded Future Identity Pack

## Overview

The Recorded Future Identity Pack for Cortex XSOAR enhances threat intelligence capabilities focused on identity-related
exposures. Integrating Recorded Future's data, this pack automates the detection, investigation, and response to
identity threats. It includes playbooks, incident types, layouts, and classifiers to streamline identity threat
management and response workflows.

## Primary Use Case

Designed for security teams managing identity-related threats, this pack helps detect compromised credentials in real
time and automatically respond to these threats. For example, when an identity exposure alert is triggered, the
integration fetches detailed information about the exposure, allowing security analysts to assess the severity and take
appropriate actions, such as enforcing password resets or disabling compromised accounts.

## Getting Started

1. **Install the Pack**:
    - From the Cortex XSOAR Marketplace, search for and install the **Recorded Future Identity Pack**.

2. **Configure the Integration**:
    - Follow the setup instructions to configure the **Recorded Future Identity** integration.

3. **Run Initial Searches**:
    - Use the **recordedfuture-identity-search** command to search for identity-related data.
    - Use the **recordedfuture-identity-lookup** command to look up detailed information about specific identities.

4. **Set Up Automated Responses**:
    - Configure playbooks and automation to respond to identity exposure alerts. Use the **Recorded Future - Identity
      Exposure** playbook as a template for handling alerts.

## Setup Instructions

To set up the Recorded Future Identity integration in Cortex XSOAR, follow these steps:

1. **Navigate to Integrations**:
    - Go to **Settings** > **Integrations** > **Instances**.

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

For detailed configuration instructions, refer to the [Recorded Future Identity Integration Documentation](https://github.com/demisto/content/blob/master/Packs/IdentityRecordedFuture/Integrations/IdentityRecordedFuture/README.md).

## Contents of the Pack

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
    - Recorded Future Identity Assessment
    - Recorded Future Identity Authorization URL
    - Recorded Future Identity Compromised Host
    - Recorded Future Identity Dump Name
    - Recorded Future Identity Exposed Hint
    - Recorded Future Identity Exposed Properties
    - Recorded Future Identity Exposed Secret
    - Recorded Future Identity Exposed Value
    - Recorded Future Identity Malware Family
    - Recorded Future Identity Name

### Layouts

- **Recorded Future Playbook Alert Identity Exposure**: Designed for the Recorded Future Identity Exposure incident type
  to provide a clear and organized view of relevant information.

### Playbooks

- **Recorded Future - Identity Exposure**: A comprehensive playbook developed as a template response when an Identity
  Exposure Playbook Alert is triggered.

### Deprecated Components

- **Incident Type**: Recorded Future Identity (Deprecated)
- **Layouts**: Recorded Future Identity Incident
- **Playbooks**:
    - Recorded Future Workforce Usecase
    - Recorded Future External Usecase
    - Recorded Future Identity - Lookup Identities (parent)
    - Recorded Future Identity - Create Incident (sub)
    - Recorded Future Identity - Identity Found (incident)

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
