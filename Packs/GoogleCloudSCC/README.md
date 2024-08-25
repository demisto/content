# Google Cloud Security Command Center
 
<~XSIAM>
 
This pack includes Cortex XSIAM content.
 

## Overview

Google Cloud Security Command Center allows you to ingest logs and data from Google Cloud Security Command Center into Cortex XSIAM.

Google Cloud Security Command Center is a platform that offers deep visibility into cloud infrastructure.
Google Cloud Security Command Center identifies security threats, and provides proactive measures to mitigate risks. 
It consolidates security-related data, offers real-time monitoring and alerts, enables continuous security assessment, and provides recommendations to improve cloud security posture.

## What does this pack do?

Google Cloud Security Command Center pack help organizations to monitor, identify and prevent security events on Google Cloud Platform, detect vulnerabilities on Google Cloud environment and provides instructions and recommendations to improve cloud security.


### This integration supports the following data:

- __Finding__ — A record of a threat, vulnerability, or misconfiguration that a certain service has found in Google Cloud environment. 
Findings show the issue that was detected, the resource that is affected by the issue, and guidance on how you can address the issue.

- __Audit__ - Google Cloud services write audit logs that record administrative activities and accesses within Google Cloud resources. 

<details>
<summary> For Google Cloud audit logs follow the below steps</summary>

1. Go to marketplace and search for *Google Cloud Logging*.
2. Install *Google Cloud Logging*.
3. Go to *Data Sources* and *Add New Instance*
4. Connect *Google Cloud Platform* data source
5. Insert subscription name (Ingest logs and data from a GCP Pub/Sub section 3)
6. Insert credentials file (Ingest logs and data from a GCP Pub/Sub section 4)
7. Select *Flow or Audit Logs*
8. Select the default values for *Vendor* and *Product*
9. Go to Query builder and use the dataset - google_cloud_logging_raw


[Ingest logs and data from a GCP Pub/Sub](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-a-GCP-Pub/Sub?tocId=RyZP~~W~YWbOPGKAClIQHg)

</details>
 
## Use Cases

1. __Vulnerability findings - Public bucket ACL:__ When a cloud storage bucket is detected as publicly accessible (that means that anyone can read/ edit the content of the bucket) the user will notified about this event and will get a recommendation on how to act regarding this issue. usually for this type of event, you will need to remove users from the bucket's members list

2. __Vulnerability findings - Open RDP Port:__ When a firewall configuration is set to have an open RDP port that allows connections from all IP addresses on TCP | UDP port 3389.
The recommendation will be to restrict firewall rules.




## Configure Google Cloud Security Command Center
 
To configure ingestion of data from Google Cloud Security Command Center follow the procedure below:
[Ingest Logs and Data from a GCP Pub/Sub](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-and-Data-from-a-GCP-Pub/Sub?tocId=q2ZnSo90ZmO~6aLgts8g5g)
 

- To configure Google Cloud Security Command Center you must have user with the corresponding permissions.
- To add inclusion filter for *Google Cloud Security Command Center Pub/ Sub Service* go to *Logging -> Log Router -> Create Sink*
and add the filter ***protoPayload.serviceName="securitycenter.googleapis.com"*** this filter will include only logs related to Security Command Center.
(Ingest logs and data from a GCP Pub/Sub section 2).
- Create Continuous Exports - go to *Security -> Settings -> CONTINUOUS EXPORTS -> CREATE PUB/ SUB EXPORT*
after naming the *continuous Exports* and describing it (optional) select or create topic.
default *Finding* query returning all finding in state *active* and that they are not *muted* (mute - hides finding from default view).
[For more Finding Query information see this documentation](https://cloud.google.com/security-command-center/docs/how-to-build-findings-query-console)
- For general *Google Cloud* audit logs ingestion, you might need additional\ different configuration on Google Cloud Platform Pub/ Sub.


## Configure Cortex XSIAM

1. Go to marketplace and install Google Cloud SCC pack
2. Go to *Data Sources* and *Add New Instance*
4. Connect *Google Cloud Platform* data source
5. Insert subscription name (Ingest logs and data from a GCP Pub/Sub section 3)
6. Insert credentials file (Ingest logs and data from a GCP Pub/Sub section 4)
7. Select Log Type *Generic*
8. Select Log Format *JSON*
8. Insert *Vendor = Google* and *Product = SCC* 
 
 
</~XSIAM>
