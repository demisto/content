## Overview

Bitsight for Security Performance Management (SPM) enables CISOs to use an external view of security performance to measure, monitor, manage, and report on their cybersecurity program performance over time, and to facilitate a universal understanding of cyber risk across their organization. This improved understanding enables security leaders to make more informed decisions about their cybersecurity programs, including where to focus limited resources to achieve the greatest impact, where to spend money, and how to manage cyber risk more effectively.

The data-driven metrics within Bitsight indicate if the cybersecurity program is performing up to the expectations set by internal goals and objectives, industry best practices, regulators, customers, and other internal or external stakeholders. The Bitsight Security Rating, the industry’s original cybersecurity rating score, provides a trusted metric that reflects the organization’s cybersecurity program performance over time. By combining the insights gained from Bitsight SPM with the Bitsight Security Rating, security leaders provide a more complete view of their cybersecurity program performance over time and help to bring about a universal understanding of cyber risk to the Board of Directors and other stakeholders.

Take action on Bitsight findings information in your security program and leverage Cortex XSOAR's incident management workflows for automation of managing security incidents. Bitsight’s visibility enables you to pinpoint and control the sources of infections in your company infrastructure, seamlessly going from awareness to rapid remediation. The findings information reveals associated IP addresses, destination ports, and more, to assist your company in connecting the security and IT teams to respond faster and more effectively to threats.

Access to and use of the Bitsight for Palo Alto Connector is subject to the [Bitsight for Palo Alto Connector Terms of Service](https://help.bitsighttech.com/hc/article_attachments/20762599625367) and [BitSight's Privacy Policy](https://www.bitsight.com/privacy-policy) (collectively, the "Bitsight Terms") as well as and any other terms of service or use noted herein.

<~XSIAM>

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
