<~XSIAM>

## Overview

Bitsight for Security Performance Management (SPM) enables CISOs to use an external view of security performance to measure, monitor, manage, and report on their cybersecurity program performance over time, and to facilitate a universal understanding of cyber risk across their organization. This improved understanding enables security leaders to make more informed decisions about their cybersecurity programs, including where to focus limited resources to achieve the greatest impact, where to spend money, and how to manage cyber risk more effectively.

## This pack includes

Data normalization capabilities:

* Modeling rules normalize logs ingested via the Cortex XSIAM event collector.
* The *`bitsight_bitsight_raw`* dataset enables querying of ingested Bitsight logs in XQL Search.

## Data Collection

### BitSight side

1. Login to [BitSight SPM](https://service.bitsighttech.com/app/spm/).
2. Click the the gear icon in the top-right corner.
3. In the dropdown menu, click on `Account`.
4. In the `User Preferences` tab, locate the `API Token` section to generate a new Token.
5. Click `Generate New Token` and use the generated token to authenticate the Bitsight integration in Cortex.

For more information, see [here](https://help.bitsighttech.com/hc/en-us).

### Cortex XSIAM side - Event Collector

To access BitSight on your Cortex XSIAM tenant:

1. Navigate to **Settings** > **Configuration** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for "BitSight Event Collector" and click **Add Instance**
3. When configuring the API Integration, set the following values:

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name | | True |
| Server URL | | True |
| API Key | The API Key used to programmatically integrate | True |
| Fetch events | | True |
| Max events per fetch | | False |
| Events Fetch Interval | | False |

####

</~XSIAM>
