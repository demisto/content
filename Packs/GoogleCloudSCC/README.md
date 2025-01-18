<!DOCTYPE html>
<html>
<head>
<h1>Google Cloud Security Command Center</h1>
</head>
<body>

<~XSOAR>
 <a href="https://xsoar.pan.dev/docs/reference/integrations/google-cloud-scc">Google Cloud SCC XSOAR integration</a>
</~XSOAR>


<h2>
Overview
</h2>

<p>
Google Cloud Security Command Center is a platform that offers deep visibility into cloud infrastructure.
<br>
It identifies security threats, and provides proactive measures to mitigate risks. 
<br>
It consolidates security-related data, offers real-time monitoring and alerts, enables continuous security assessment, and provides recommendations to improve cloud security posture.
</p>

<~XSIAM>

<h2> What does this pack do?</h2>
<p>
The Google Cloud Security Command Center content pack helps organizations to monitor, identify and prevent security events on Google Cloud Platform, detects vulnerabilities on Google Cloud environments and provides instructions and recommendations to improve cloud security.
</p>
<br>

<h3> Log normalization supports the following data:</h3>

<strong>Finding</strong> — A record of a threat, vulnerability, or misconfiguration that a certain service was found in a Google Cloud environment. 
Findings show the issue that was detected, the resource that is affected by the issue, and guidance on how you can address the issue.
<br>
<br>

<details>
<summary> For <a href="https://cloud.google.com/logging/docs/audit">Google Cloud audit logs normalization </a>, follow this procedure:</summary>
<p>

<a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-a-GCP-Pub/Sub?tocId=RyZP~~W~YWbOPGKAClIQHg">Ingest logs and data from a GCP Pub/Sub</a>
<br><br>

1. Go to Marketplace and search for <i><strong>Google Cloud Logging</i></strong>.<br>
2. Install <i><strong>Google Cloud Logging</i></strong>.<br>
3. Go to <i><strong>Data Sources</i></strong> and <i><strong>Add New Instance</i></strong>.<br>
4. Connect the <i><strong>Google Cloud Platform</i></strong> data source.<br>
5. Insert subscription name.<br>
6. Insert credentials file.<br>
7. Select <i><strong>Flow or Audit Logs</i></strong>.<br>
8. Go to the Query builder and use the dataset - google_cloud_logging_raw.<br>

</p>
<h4> Note </h4>
<p>
To include audit logs related to Google Cloud Security Command Center only, you need to add an inclusion filter on the log router sink. <br>
Add the filter <i><strong>protoPayload.serviceName="securitycenter.googleapis.com"</i></strong> <br>
as describe in <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-a-GCP-Pub/Sub?tocId=RyZP~~W~YWbOPGKAClIQHg">section 2.c</a>. <br>
</p>
</details>
<br>

<details>
<summary> 
For sample use cases click here.
</summary>
<h3>Use Cases</h3>
<p>
1. <strong>Vulnerability findings - Public bucket ACL:</strong> When a cloud storage bucket is detected as publicly accessible (that means that anyone can read/ edit the content of the bucket) the user will be notified about this event and will get a recommendation on how to act regarding this issue. <br> 
Usually for this type of event, you will need to remove users from the bucket's members list.
</p>
<p>
2. <strong>Vulnerability findings - Open RDP Port:</strong> When a firewall configuration is set to have an open RDP port that allows connections from all IP addresses on TCP | UDP port 3389. <br>
The recommendation will be to restrict firewall rules.
</p>

</details>

<br>


<h2>Configure Google Cloud Security Command Center</h2>
 <p>
To configure ingestion of data from Google Cloud Security Command Center follow the procedure in: <br>
<a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-a-GCP-Pub/Sub?tocId=RyZP~~W~YWbOPGKAClIQHg">Ingest logs and data from a GCP Pub/Sub</a>
</p>
<br> 
 

<h2> Configure Cortex XSIAM </h2>
<p>
1. Go to Marketplace and install the Google Cloud SCC pack.<br>
2. Go to <i><strong>Data Sources</i></strong> and <i><strong>Add New Instance</i></strong>.<br>
3. Connect the <i><strong>Google Cloud Platform</i></strong> data source.<br>
4. Insert the subscription name (Ingest logs and data from a GCP Pub/Sub section 3).<br>
5. Insert the credentials file (Ingest logs and data from a GCP Pub/Sub section 4).<br>
6. Select Log Type <i><strong>Generic</i></strong>.<br>
7. Select Log Format <i><strong>JSON</i></strong>.<br>
8. Insert <i><strong>Vendor = Google</i></strong> and <i><strong>Product = SCC</i></strong>.<br>
</p>
<br> 

<h4> Notes </h4>
<p>
* To configure Google Cloud Security Command Center you must be a user with the corresponding permissions, for example: <br>
1. Pub/ Sub Admin.<br>
2. Security Center Admin Viewer.<br>
3. View Service Accounts.<br>
* To create Continuous Exports, go to <i><strong>Security -> Settings -> CONTINUOUS EXPORTS -> CREATE PUB/ SUB EXPORT</i></strong> <br>
After naming the <i><strong>continuous Exports</i></strong> and describing it (optional) select or create the topic. <br>
The default <i><strong>Finding</i></strong> query returns all findings in the <i><strong>active</i></strong> state and that are not <i><strong>muted</i></strong> (mute - hides finding from default view).<br>
<a href="https://cloud.google.com/security-command-center/docs/how-to-build-findings-query-console">For more Finding Query information, see this documentation</a> <br>
* For general <i><strong>Google Cloud</i></strong> audit logs ingestion, you might need additional or a different configuration on Google Cloud Platform Pub/Sub.

</p>
<br>
 
</body>
</html>
 

</~XSIAM>
