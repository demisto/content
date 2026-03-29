# SpecterOps BloodHound Enterprise (BHE) Content Pack

## Overview

BloodHound Enterprise reduces risk in Active Directory and Microsoft Azure environments by continuously identifying and quantifying attack paths that attackers use to escalate privileges. The SpecterOpsBHE content pack enables automated retrieval of attack path findings from BloodHound Enterprise into Cortex XSOAR, streamlining incident creation, investigation, and remediation workflows.

This pack provides comprehensive integration capabilities that help security teams proactively identify privilege escalation paths, automate incident response, and reduce the attack surface in enterprise environments.

## What does this pack do?

This content pack provides end-to-end automation for managing BloodHound Enterprise attack path findings within Cortex XSOAR. The pack includes:

### Core Capabilities

- **Automated Attack Path Ingestion**: Automatically fetches attack path findings from BloodHound Enterprise and creates incidents in Cortex XSOAR with detailed remediation guidance
- **Object and Asset Intelligence**: Query object IDs by name and retrieve comprehensive asset information for security principals
- **Path Analysis**: Check for path existence between security principals to validate attack paths and understand relationships
- **Incident Management**: Dedicated incident type, layout, and playbook for managing BloodHound Enterprise attack path incidents

### Key Features

- **Continuous Monitoring**: Configurable fetch intervals to continuously monitor for new attack paths
- **Detailed Remediation Guidance**: Each incident includes short and long remediation steps from BloodHound Enterprise
- **Multi-Environment Support**: Filter attack paths by environment (domain) and finding category
- **Comprehensive Asset Data**: Retrieve detailed information about users, computers, groups, and Azure objects
- **Automated Investigation**: Playbook-driven investigation workflow for attack path incidents

## Use Cases

### 1. Proactive Attack Path Remediation

Security teams can automatically receive notifications about newly discovered attack paths in their Active Directory and Azure environments. Each incident includes:

- Detailed description of the attack path
- Impact and exposure metrics
- Step-by-step remediation guidance
- Affected security principals and their relationships

**Workflow:**

1. BloodHound Enterprise continuously analyzes your environment
2. New attack paths are automatically ingested into Cortex XSOAR as incidents
3. Security analysts review incidents with detailed remediation steps
4. Remediation actions are tracked and validated

### 2. Security Principal Investigation

When investigating a security incident or performing threat hunting, analysts can quickly:

- Look up object IDs for users, computers, or groups by name
- Retrieve comprehensive asset information including group memberships, permissions, and relationships
- Verify if attack paths exist between specific security principals

**Workflow:**

1. Analyst identifies a suspicious user or computer during investigation
2. Uses `bhe-object-id-get` to find the object ID
3. Uses `bhe-asset-info-get` to retrieve detailed asset information
4. Uses `bhe-path-exist` to check if paths exist to high-value targets
5. Takes appropriate remediation actions based on findings

### 3. Compliance and Risk Assessment

Organizations can use this pack to:

- Maintain an inventory of all attack paths in their environment
- Track remediation progress over time
- Generate reports on attack path trends and patterns
- Demonstrate compliance with security policies

### 4. Automated Response to Privilege Escalation

When an attack path is identified, the playbook can:

- Automatically enrich incident data with asset information
- Check for related attack paths
- Assign incidents based on severity and impact
- Track remediation status

## Pack Components

This pack includes the following components:

### Integration

- **SpecterOpsBHE**: Main integration for connecting to BloodHound Enterprise API
  - Fetches attack path findings automatically
  - Provides commands for querying objects and assets
  - Supports filtering by environment and finding category

### Playbooks

- **SpecterOpsBHE**: Automated playbook for investigating and responding to attack path incidents
  - Enriches incident data with object information
  - Provides structured investigation workflow
  - Supports manual and automated remediation tracking

### Incident Types

- **SpecterOpsBHE Attack Path**: Dedicated incident type for BloodHound Enterprise attack path findings
  - Custom fields for attack path metadata
  - Severity mapping based on BloodHound Enterprise severity levels
  - Structured data for impact and exposure metrics

### Layouts

- **SpecterOpsBHE Attack Path Layout**: Custom layout for viewing and managing attack path incidents
  - Displays attack path details
  - Shows affected security principals
  - Provides access to remediation guidance
  - Tracks investigation and remediation progress

## Setup and Configuration

### Prerequisites

- BloodHound Enterprise tenant with API access
- API Token ID and Token Key from BloodHound Enterprise
- Cortex XSOAR instance (version 6.0.0 or higher)

### Installation

1. Install the SpecterOpsBHE pack from the Cortex XSOAR Marketplace
2. Configure the SpecterOpsBHE integration instance:
   - **BloodHound Enterprise Domain**: Your BHE tenant URL (e.g., `https://example.bloodhoundenterprise.io`)
   - **Token ID**: Your BloodHound Enterprise API Token ID
   - **Token Key**: Your BloodHound Enterprise API Token Key
   - **Finding Environment**: Filter by specific domains or use "all" for all environments
   - **Finding Category**: Filter by finding category or use "all" for all categories
   - **Fetch incidents**: Enable to automatically fetch attack paths
   - **Incidents Fetch Interval**: Set the interval for fetching (default: 10 minutes)
   - **Incident type**: Set to "SpecterOpsBHE Attack Path"

### Obtaining API Credentials

1. Log in to your BloodHound Enterprise tenant
2. Navigate to **My Profile** from the left sidebar
3. Select **API Key Management**
4. Click **Create Token**
5. Enter a descriptive name for the token and click **Save**
6. Copy and securely store the displayed API Key/ID pair
7. Click **Close**

**Important**: The API Key/ID pair is only displayed once. Store it securely.

### Proxy Configuration (Optional)

If your environment requires proxy access:

- Configure **Proxy URL**, **Proxy URL Username**, and **Proxy URL Password** in the integration settings

## How to Use This Pack

### Automatic Attack Path Ingestion

Once configured with "Fetch incidents" enabled, the integration will:

1. Connect to BloodHound Enterprise at the configured interval
2. Retrieve new attack path findings
3. Create incidents in Cortex XSOAR with all relevant details
4. Include remediation guidance and affected principal information

### Manual Investigation Commands

#### Get Object ID by Name

Use the `bhe-object-id-get` command to retrieve the unique object ID for a security principal (user, computer, group, etc.) by providing its name. This is useful when you need to look up an object ID before performing other operations.

**Command:**

!bhe-object-id-get object_names="USERNAME@example.com"

The command returns the object ID, status, and message for each object name provided. You can query multiple objects by providing a comma-separated list.

#### Get Asset Information

Use the `bhe-asset-info-get` command to retrieve comprehensive information about a security principal using its object ID. This includes details such as name, type, domain, enabled status, group memberships, and other properties.

**Command:**

!bhe-asset-info-get object_ids="12345678-1234-1234-1234-123456789abc,87654321-4321-4321-4321-cba987654321"

The command returns the asset information, status, and message for each object IDs provided. You can query multiple objects by providing a comma-separated list.

#### Check Path Existence

Use the `bhe-path-exist` command to verify if an attack path exists between two security principals. This helps validate relationships and understand potential privilege escalation routes.

**Command:**

!bhe-path-exist from_principal="12345678-1234-1234-1234-123456789abc" to_principal="87654321-4321-4321-4321-cba987654321"

The command returns a boolean value indicating whether a path exists between the specified nodes, along with status and message information.
