# Magnet Automate

## Overview
Magnet Automate is an enterprise-level digital forensics orchestration and automation platform designed to streamline and accelerate the processing of forensic evidence. By integrating Magnet Automate with Cortex XSOAR, labs can eliminate manual hand-offs, reduce backlogs, and ensure consistent, repeatable workflows across their entire forensic toolkit.

## Key Features
*   **Automate Forensic Workflows**: Orchestrate complex forensic processes from acquisition to reporting.
*   **Manage Cases**: Programmatically create and manage cases within the Magnet Automate environment.
*   **Scale Lab Capacity**: Maximize hardware utilization and scale processing power to handle increasing data volumes.
*   **Standardized Processing**: Ensure every case follows a defined, defensible procedure.

## Setup Instructions

### Prerequisites
To configure this integration, you will need:
1.  A valid Magnet Automate instance.
2.  An API Key generated from the Magnet Automate interface.
3.  The Server URL of your Magnet Automate instance.

### Obtaining the API Key
1.  Log in to your Magnet Automate interface.
2.  Navigate to the **Settings** or **API Management** section (refer to your Magnet Automate version documentation for the exact location).
3.  Generate a new API Key and copy it for use in the XSOAR integration configuration.

### Server URL Format
The Server URL must be provided in the following format:
`https://{hostName}:{port}`
Example: `https://automate.example.com:5000`

## Authentication
The integration uses API Key authentication. All requests include the API Key in the `X-API-KEY` HTTP header.

## Usage Notes
### Custom Fields
Magnet Automate allows for the definition of custom fields for cases. To ensure successful case creation, it is recommended to use the `ma-forensics-custom-fields-list` command. This command retrieves a list of all available custom fields and their requirements, which can then be mapped to the case creation arguments in XSOAR.
