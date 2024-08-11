# Fortinet FortiNDR Cloud Integration for Cortex XSOAR

### FortiNDR Cloud Overview

Fortinet FortiNDR Cloud is a cloud-based network detection and response solution built for the rapid detection of threat activity, investigation of suspicious behavior, proactive hunting for potential risks, and directing a fast and effective response to active threats.

### Integration Overview

The Fortinet FortiNDR Cloud Cortex XSOAR integration enables security teams to utilize the features and functionality of the FortiNDR Cloud solution with their existing Cortex XSOAR deployment. The integration leverages FortiNDR Cloud’s fully RESTful APIs to interact with the FortiNDR Cloud backend to introduce specific data sets into Cortex XSOAR. This document contains all the necessary information to configure, install, and use the integration.

For more information about the Cortex XSOAR integration visit the FortiNDR Cloud help documentation here: <https://docs.fortinet.com/document/fortindr-cloud/latest/cortex-xsoar-integration-guide>

#### Installation

To install the integration:

1. Navigate to the Settings section of the Cortex XSOAR interface. Ensure you are on the Integration tab and Instances sub-tab. In the Search box, type “Fortinet FortiNDR Cloud” to search for the integration.

  Alternatively, you can manually install the integration using the integration-Fortinet_FortiNDR_Cloud.yml file available on Fortinet’s GitHub repository (here). Once you have the file downloaded, select the Upload button on the Settings page
2. Click the Add Instance link to create a new instance of the add-on.
3. In the settings, enter a Name for the instance, and a valid FortiNDR Cloud API Key. (in the FortiNDR Cloud portal, navigate to the Profile Settings page to create a new API key).

  Optional - Select the Fetches Incidents option to have the integration periodically pull new detections from FortiNDR Cloud into Cortex XSOAR. Note: This will pull ALL events your portal account has access to unless you specify a specific account UUID.
      Optional – Choose the default Incident Type category for new incidents. The integration automatically categorizes incidents based on their FortiNDR Cloud detection rule category.
4. Choose either Use Single Engine or Use Load-Balancing Group depending on your Cortex XSOAR deployment.
5. Click the Test button to test the instance. If the instance can connect to the FortiNDR Cloud APIs, you should see a successful message like the one above.
6. Lastly, click the Done button to complete the installation of the integration.

#### Commands

The integration includes several commands that can be executed within Cortex XSOAR to interact with Fortinet FortiNDR Cloud. Below is a list of all the commands and the following sections detail the arguments for each command.

| Command | Description |
| --- | --- |
| fortindr-cloud-get-sensors | Get a list of all sensors |
| fortindr-cloud-get-devices | Get a list of all devices. |
| fortindr-cloud-get-tasks | Get a list of all the PCAP tasks |
| fortindr-cloud-create-task | Create a new PCAP task |
| fortindr-cloud-get-detections | Get a list of detections |
| fortindr-cloud-get-detection-rules | Get a list of detection rules |
| fortindr-cloud-resolve-detection | Resolve a specific detection |
| fortindr-cloud-get-detection-rule-events | Get a list of the events that matched on a specific rule |
| fortindr-cloud-create-detection-rule | Create a new detection rule |
| fortindr-cloud-get-entity-summary | Get summary information about an IP or domain. |
| fortindr-cloud-get-entity-pdns | Get passive DNS information about an IP or domain |
| fortindr-cloud-get-entity-dhcp| Get DHCP information about an IP address |
| fortindr-cloud-get-entity-file | Get information about a file |
| fortindr-cloud-get-telemetry-events | Get event telemetry data grouped by time |
| fortindr-cloud-get-telemetry-network | Get network telemetry data grouped by time |
| fortindr-cloud-get-telemetry-packetstats | Get network metrics to a given sensor's interfaces |
