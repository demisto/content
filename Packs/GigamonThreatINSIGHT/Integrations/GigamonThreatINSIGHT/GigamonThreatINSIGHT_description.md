# Gigamon Insight Integration for Cortex XSOAR

### Insight Overview

Gigamon Insight is a cloud-based network detection and response solution built for the rapid detection of threat activity, investigation of suspicious behavior, proactive hunting for potential risks, and directing a fast and effective response to active threats.

### Integration Overview

The Gigamon Insight Cortex XSOAR integration enables security teams to utilize the features and functionality of the Insight solution with their existing Cortex XSOAR deployment. The integration leverages Insight’s fully RESTful APIs to interact with the Insight backend to introduce specific data sets into Cortex XSOAR. This document contains all the necessary information to configure, install, and use the integration.

For more information about the Cortex XSOAR integration visit the Insight help documentation here: <https://insight.gigamon.com/help/api/apidocs-demisto>

#### Installation

To install the integration:

1. Navigate to the Settings section of the Cortex XSOAR interface. Ensure you are on the Integration tab and Servers & Services sub-tab. In the Search box, type “Gigamon Insight” to search for the integration.

  Alternatively, you can manually install the integration using the integration-Gigamon_Insight.yml file available on Cortex XSOAR’s GitHub repository (here). Once you have the file downloaded, select the Upload button on the Settings page
2. Click the Add Instance link to create a new instance of the add-on.
3. In the settings, enter a Name for the instance, and a valid Insight API Key. (in the Insight portal, navigate to the Profile Settings page to create a new API key).

  Optional - Select the Fetches Incidents option to have the integration periodically pull new detections from Insight into Cortex XSOAR. Note: This will pull ALL events your portal account has access to unless you specify a specific account UUID.
      Optional – Choose the default Incident Type category for new incidents. The integration automatically categorizes incidents based on their Insight detection rule category.
4. Choose either Use Single Engine or Use Load-Balancing Group depending on your Cortex XSOAR deployment.
5. Click the Test button to test the instance. If the instance can connect to the Insight APIs, you should see a successful message like the one above.
6. Lastly, click the Done button to complete the installation of the integration.

#### Commands

The integration includes several commands available to execute within Cortex XSOAR to interact with Gigamon Insight. Below is a list of all the commands and the following sections detail the arguments for each command.

| Command | Description |
| --- | --- |
| insight-get-events | Perform a search for network events from Insight |
| insight-get-history | Get user's query history |
| insight-get-saved-searches | Get user's saved searches |
| insight-get-sensors | Get a list of all sensors |
| insight-get-devices | Get the number of devices |
| insight-get-tasks | Get a list of all the PCAP tasks |
| insight-create-task | Create a new PCAP task |
| insight-get-detections | Get a list of detections |
| insight-get-detection-rules | Get a list of detection rules |
| insight-resolve-detection | Resolve a specific detection |
| insight-get-detection-rule-events | Get a list of the events that matched on a specific rule |
| insight-create-detection-rule | Create a new detection rule |
| insight-get-entity-summary | Get entity summary information about an IP or domain |
| insight-get-entity-pdns | Get passive DNS information about an IP or domain |
| insight-get-entity-dhcp| Get DHCP information about an IP address |
| insight-get-entity-file | Get entity information about a file |
| insight-get-telemetry-events | Get event telemetry data grouped by time |
| insight-get-telemetry-network | Get network telemetry data grouped by time |
| insight-get-telemetry-packetstats | Get network metrics to a given sensor's interfaces |