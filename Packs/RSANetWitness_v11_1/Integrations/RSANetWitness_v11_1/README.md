<!-- HTML_DOC -->
<p>Use the RSA NetWitness integration for systems Logs, Network, and endpoint visibility for real-time collection, detection, and automated response on Cortex XSOAR.</p>
<p>Providing full session analysis, customers can extract critical data and effectively operate security operations automated playbook.</p>
<h2>Use Cases</h2>
<hr>
<ul>
<li>Monitor NetWitness incidents.</li>
<li>Update existing incident.</li>
<li>Query incidents in a specific time frame.</li>
</ul>
<h2>Prerequisites</h2>
<hr>
<p>You need the server URL and a valid NetWitness account before configuring a new instance.</p>
<h2>Required Permissions</h2>
<hr>
<p>The following permission is required for all commands.</p>
<ul>
<li>integration-server.api.access</li>
</ul>
<h2>Configure RSA Netwitness on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for RSA netwitness.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: A textual name for the integration instance.</li>
<li>
<strong>Server URL</strong>: Exchange server URL.</li>
<li>
<strong>Credentials</strong>: Your personal account username.</li>
<li>
<strong>Password</strong>: Your personal account password.</li>
<li>
<strong>Fetched incidents data</strong>: The integration imports NetWitness incident, and all alerts related, as Cortex XSOAR incident. All incidents created 24 hours prior to the configuration of ‘Fetch-incidents’  and up to current time will be imported.</li>
<li>
<strong>On Fetch incidents, import all alerts related to the incident</strong>.</li>
<li>
<strong>Fetch time: </strong>First fetch timestamp.</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<h2>Fetched Incidents Data</h2>
<hr>
<p>To use Fetch incidents, select the <strong>Fetch Incidents</strong> checkbox when configuring a new integration instance.</p>
<p>By default, the integration will import NetWitness incidents data as Cortex XSOAR incidents.</p>
<p>To import related alerts data in addition to the incidents data, select the relevant checkbox in the instance settings.</p>
<p>All incidents created 24 hours prior to the configuration of <strong>Fetch Incidents</strong> and up to current time will be imported.</p>
<ul><li>Note - Due to API limitations, the first few attempts to fetch incidents may fail. If the fetch fails, you can either change the value of the "First fetch timestamp" parameter to fetch a smaller number of incidents or set the timeout of the fetch incidents command of the integration to a higher value.</li></ul>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_c7ca61c6-e51d-4664-9222-c8ee6b66dcad" target="_self">Get details for a specific incident: netwitness-get-incident</a></li>
<li><a href="#h_c527c29d-dbad-48a5-a47d-2285b7eadfc0" target="_self">Get a list of incidents: netwitness-get-incidents</a></li>
<li><a href="#h_2b24155b-c035-4450-9601-928a4778bbe9" target="_self">Update an incident: netwitness-update-incident</a></li>
<li><a href="#h_42f04935-4255-4322-afa7-1d8486afb65c" target="_self">Delete an incident: netwitness-delete-incident</a></li>
<li><a href="#h_ea23ce95-17e1-4395-84f9-422c83f30955" target="_self">Get all alerts for an incident: netwitness-get-alerts</a></li>
</ol>
<h3 id="h_c7ca61c6-e51d-4664-9222-c8ee6b66dcad">1. Get details for a specific incident</h3>
<hr>
<p>Get details of a specific incident, including all alerts related with the incident.</p>
<h5>Base Command</h5>
<p><code>netwitness-get-incident</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 291px;"><strong>Argument Name</strong></th>
<th style="width: 245px;"><strong>Description</strong></th>
<th style="width: 172px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291px;">incidentId</td>
<td style="width: 245px;">The incident ID</td>
<td style="width: 172px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 334.667px;"><strong>Path</strong></th>
<th style="width: 304.333px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.id</td>
<td style="width: 304.333px;">The unique identifier of the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.title</td>
<td style="width: 304.333px;">Title of the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.summary</td>
<td style="width: 304.333px;">Summary of the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.priority</td>
<td style="width: 304.333px;">The incident priority.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.riskScore</td>
<td style="width: 304.333px;">Incident risk score calculated based on associated alert’s risk score. Risk score ranges from 0 (no risk) to 100 (highest risk).</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.status</td>
<td style="width: 304.333px;">The current status.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.alertCount</td>
<td style="width: 304.333px;">Number of alerts associated with the Incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.averageAlertRiskScore</td>
<td style="width: 304.333px;">Average risk score of the alerts associated with the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.sealed</td>
<td style="width: 304.333px;">Indicates if additional alerts can be associated with an incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.totalRemediationTaskCount</td>
<td style="width: 304.333px;">The number of total remediation tasks for the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.openRemediationTaskCount</td>
<td style="width: 304.333px;">The number of open remediation tasks for the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.created</td>
<td style="width: 304.333px;">The timestamp of when the incident is created.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.lastUpdated</td>
<td style="width: 304.333px;">The timestamp of when the incident was last updated.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.lastUpdatedBy</td>
<td style="width: 304.333px;">The NetWitness user identifier of the user who last updated the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.assignee</td>
<td style="width: 304.333px;">The NetWitness user identifier of the user currently working on the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.sources</td>
<td style="width: 304.333px;">Unique set of sources for all of the Alerts in the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.ruleId</td>
<td style="width: 304.333px;">The unique identifier of the rule that created the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.firstAlertTime</td>
<td style="width: 304.333px;">The timestamp of the earliest occurring Alert in this incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.categories.id</td>
<td style="width: 304.333px;">The unique category identifier.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.categories.parent</td>
<td style="width: 304.333px;">Parent name of the category.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.categories.name</td>
<td style="width: 304.333px;">Friendly name of the category.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.journalEntries.id</td>
<td style="width: 304.333px;">The unique journal entry identifier.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.journalEntries.author</td>
<td style="width: 304.333px;">The author of this entry.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.journalEntries.notes</td>
<td style="width: 304.333px;">Notes and observations about the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.journalEntries.created</td>
<td style="width: 304.333px;">The timestamp of the journal entry created date.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.journalEntries.lastUpdated</td>
<td style="width: 304.333px;">The timestamp of the journal entry last updated date.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.journalEntries.milestone</td>
<td style="width: 304.333px;">Incident milestone classifier.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.createdBy</td>
<td style="width: 304.333px;">The NetWitness user id or name of the rule that created the incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.deletedAlertCount</td>
<td style="width: 304.333px;">The number of alerts that are deleted from theincident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.eventCount</td>
<td style="width: 304.333px;">Number of events associated with incident.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.alertMeta.SourceIp</td>
<td style="width: 304.333px;">Unique source IP addresses.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Incidents.alertMeta.DestinationIp</td>
<td style="width: 304.333px;">Unique destination IP addresses.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.id</td>
<td style="width: 304.333px;">The unique alert identifier.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.incidentId</td>
<td style="width: 304.333px;">The incident id associated with the alert.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.title</td>
<td style="width: 304.333px;">The title or name of the rule that created the alert.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.detail</td>
<td style="width: 304.333px;">The details of the alert. This can be the module name or meta that the module included.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.created</td>
<td style="width: 304.333px;">The timestamp of the alert created date.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.source</td>
<td style="width: 304.333px;">The source of this alert. For example, "Event Stream Analysis", "Malware Analysis", etc.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.riskScore</td>
<td style="width: 304.333px;">The risk score of this alert, usually in the range 0 - 100.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.type</td>
<td style="width: 304.333px;">Type of alert, "Network", "Log", etc.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.source.device.ipAddress</td>
<td style="width: 304.333px;">The IP address.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.source.device.port</td>
<td style="width: 304.333px;">The port.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.source.device.macAddress</td>
<td style="width: 304.333px;">The ethernet MAC address.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.source.device.dnsHostname</td>
<td style="width: 304.333px;">The DNS resolved hostname.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.source.device.dnsDomain</td>
<td style="width: 304.333px;">The top-level domain from the DNS resolved hostname</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.source.user.username</td>
<td style="width: 304.333px;">The unique username.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.source.user.emailAddress</td>
<td style="width: 304.333px;">An email address.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.source.user.adUsername</td>
<td style="width: 304.333px;">An Active Directory (AD) username.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.source.user.adDomain</td>
<td style="width: 304.333px;">An Active Directory (AD) domain</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.destination.device.ipAddress</td>
<td style="width: 304.333px;">The IP address.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.destination.device.port</td>
<td style="width: 304.333px;">The port.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.destination.device.macAddress</td>
<td style="width: 304.333px;">The ethernet MAC address.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.destination.device.dnsHostname</td>
<td style="width: 304.333px;">The DNS resolved hostname.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.destination.device.dnsDomain</td>
<td style="width: 304.333px;">The top-level domain from the DNS resolved hostname</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.destination.user.username</td>
<td style="width: 304.333px;">The unique username.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.destination.user.emailAddress</td>
<td style="width: 304.333px;">An email address.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.destination.user.adUsername</td>
<td style="width: 304.333px;">An Active Directory (AD) username.</td>
</tr>
<tr>
<td style="width: 334.667px;">NetWitness.Alerts.events.destination.user.adDomain</td>
<td style="width: 304.333px;">An Active Directory (AD) domain</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!NetWitness -get-incident incidentId="INC-1"</pre>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Alerts<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>created<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-03-15T16:39:18.777Z<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>detail<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>events<span class="pl-pds">"</span></span>: [
                {
                    <span class="pl-s"><span class="pl-pds">"</span>destination<span class="pl-pds">"</span></span>: {
                        <span class="pl-s"><span class="pl-pds">"</span>device<span class="pl-pds">"</span></span>: {
                            <span class="pl-s"><span class="pl-pds">"</span>dnsDomain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>dnsHostname<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>ipAddress<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>192.168.5.###<span class="pl-pds">"</span></span>,
                            <span class="pl-s"><span class="pl-pds">"</span>macAddress<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>00:0C:29:62:29:##<span class="pl-pds">"</span></span>,
                            <span class="pl-s"><span class="pl-pds">"</span>port<span class="pl-pds">"</span></span>: <span class="pl-c1">23</span>
                        },
                        <span class="pl-s"><span class="pl-pds">"</span>user<span class="pl-pds">"</span></span>: {
                            <span class="pl-s"><span class="pl-pds">"</span>adDomain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>adUsername<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>emailAddress<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>username<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>administrator<span class="pl-pds">"</span></span>
                        }
                    },
                    <span class="pl-s"><span class="pl-pds">"</span>domain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                    <span class="pl-s"><span class="pl-pds">"</span>eventSource<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                    <span class="pl-s"><span class="pl-pds">"</span>eventSourceId<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>7<span class="pl-pds">"</span></span>,
                    <span class="pl-s"><span class="pl-pds">"</span>source<span class="pl-pds">"</span></span>: {
                        <span class="pl-s"><span class="pl-pds">"</span>device<span class="pl-pds">"</span></span>: {
                            <span class="pl-s"><span class="pl-pds">"</span>dnsDomain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>dnsHostname<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>ipAddress<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>192.168.5.###<span class="pl-pds">"</span></span>,
                            <span class="pl-s"><span class="pl-pds">"</span>macAddress<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>00:0C:29:D1:39:##<span class="pl-pds">"</span></span>,
                            <span class="pl-s"><span class="pl-pds">"</span>port<span class="pl-pds">"</span></span>: <span class="pl-c1">1045</span>
                        },
                        <span class="pl-s"><span class="pl-pds">"</span>user<span class="pl-pds">"</span></span>: {
                            <span class="pl-s"><span class="pl-pds">"</span>adDomain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>adUsername<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>emailAddress<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>username<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>administrator<span class="pl-pds">"</span></span>
                        }
                    }
                }
            ],
            <span class="pl-s"><span class="pl-pds">"</span>id<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>5aaaa1b69a95133336911c93<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>incidentId<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>INC-12<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>riskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
            <span class="pl-s"><span class="pl-pds">"</span>source<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>NetWitness Investigate<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>title<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Network Alert1<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>type<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Network<span class="pl-pds">"</span></span>
        },
        <span class="pl-s"><span class="pl-pds">"</span>Incidents<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>alertCount<span class="pl-pds">"</span></span>: <span class="pl-c1">1</span>,
            <span class="pl-s"><span class="pl-pds">"</span>alertMeta<span class="pl-pds">"</span></span>: {
                <span class="pl-s"><span class="pl-pds">"</span>DestinationIp<span class="pl-pds">"</span></span>: [
                    <span class="pl-s"><span class="pl-pds">"</span>192.168.5.###<span class="pl-pds">"</span></span>
                ],
                <span class="pl-s"><span class="pl-pds">"</span>SourceIp<span class="pl-pds">"</span></span>: [
                    <span class="pl-s"><span class="pl-pds">"</span>192.168.5.###<span class="pl-pds">"</span></span>
                ]
            },
            <span class="pl-s"><span class="pl-pds">"</span>assignee<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>averageAlertRiskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
            <span class="pl-s"><span class="pl-pds">"</span>categories<span class="pl-pds">"</span></span>: [],
            <span class="pl-s"><span class="pl-pds">"</span>created<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-03-15T16:39:18.802Z<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>createdBy<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>admin<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>deletedAlertCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
            <span class="pl-s"><span class="pl-pds">"</span>eventCount<span class="pl-pds">"</span></span>: <span class="pl-c1">1</span>,
            <span class="pl-s"><span class="pl-pds">"</span>firstAlertTime<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>id<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>INC-12<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>journalEntries<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>lastUpdated<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-03-16T05:51:03.233Z<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>lastUpdatedBy<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>admin<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>openRemediationTaskCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
            <span class="pl-s"><span class="pl-pds">"</span>priority<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Medium<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>riskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
            <span class="pl-s"><span class="pl-pds">"</span>ruleId<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>sealed<span class="pl-pds">"</span></span>: <span class="pl-c1">false</span>,
            <span class="pl-s"><span class="pl-pds">"</span>sources<span class="pl-pds">"</span></span>: [
                <span class="pl-s"><span class="pl-pds">"</span>NetWitness Investigate<span class="pl-pds">"</span></span>
            ],
            <span class="pl-s"><span class="pl-pds">"</span>status<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>New<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>summary<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span><span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>title<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Network Alert1<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>totalRemediationTaskCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>
        }
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h2>Incident INC-12 Alerts</h2>
<h3>Alert Details</h3>
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Title</th>
<th>Detail</th>
<th>Created</th>
<th>Source</th>
<th>Risk score</th>
<th>Type</th>
<th>Total events</th>
</tr>
</thead>
<tbody>
<tr>
<td>5aaaa1b69a95133336911c93</td>
<td>Network Alert1</td>
<td> </td>
<td>2018-03-15T16:39:18.777Z</td>
<td>NetWitness Investigate</td>
<td>50</td>
<td>Network</td>
<td>1</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Event Details</h3>
<p><em>Domain:</em> None<br> <em>Source:</em> None<br> <em>ID:</em> 7</p>
<h3>Source</h3>
<table style="width: 748px;" border="2">
<thead>
<tr>
<th style="width: 164.333px;">Device IP</th>
<th style="width: 146.667px;">Device Port</th>
<th style="width: 228px;">Device MAC</th>
<th style="width: 195px;">User UserName</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 164.333px;">192.168.5.189</td>
<td style="width: 146.667px;">1045</td>
<td style="width: 228px;">00:0C:29:D1:39:5D</td>
<td style="width: 195px;">administrator</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Destination</h3>
<table style="width: 748px;" border="2">
<thead>
<tr>
<th style="width: 166.667px;">Device IP</th>
<th style="width: 147.333px;">Device Port</th>
<th style="width: 224px;">Device MAC</th>
<th style="width: 196px;">User UserName</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 166.667px;">192.168.5.172</td>
<td style="width: 147.333px;">23</td>
<td style="width: 224px;">00:0C:29:62:29:43</td>
<td style="width: 196px;">administrator</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_c527c29d-dbad-48a5-a47d-2285b7eadfc0">2. Get a list of incidents</h3>
<hr>
<p>Get a list of incidents in a specific time frame. All arguments are optional, but you need to specify at least one argument for the command to execute successfully.</p>
<h5>Base Command</h5>
<p><code>netwitness-get-incidents</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 496px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">since</td>
<td style="width: 496px;">Timestamp in ISO 8601 format (2018-01-01T14:00:00.000Z). Use to retrieve incidents created on and after this timestamp.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">until</td>
<td style="width: 496px;">Timestamp in ISO 8601 format (2018-01-01T14:00:00.000Z). Use to retrieve incidents created on and before this timestamp.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">limit</td>
<td style="width: 496px;">Maximum number of incidents to retrieve. Default is 200.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">lastDays</td>
<td style="width: 496px;">Use this to retrieve incidents from the previous number of days.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 338.667px;"><strong>Path</strong></th>
<th style="width: 381.333px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.id</td>
<td style="width: 381.333px;">Unique identifier of the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.title</td>
<td style="width: 381.333px;">Title of the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.summary</td>
<td style="width: 381.333px;">Summary of the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.priority</td>
<td style="width: 381.333px;">The incident priority</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.riskScore</td>
<td style="width: 381.333px;">Incident risk score calculated based on associated alert’s risk score. Risk score ranges from 0 (no risk) to 100 (highest risk).</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.status</td>
<td style="width: 381.333px;">The current status of the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.alertCount</td>
<td style="width: 381.333px;">Number of alerts associated with the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.averageAlertRiskScore</td>
<td style="width: 381.333px;">Average risk score of the alerts associated with the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.sealed</td>
<td style="width: 381.333px;">Indicates if additional alerts can be associated with an incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.totalRemediationTaskCount</td>
<td style="width: 381.333px;">The number of total remediation tasks for the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.openRemediationTaskCount</td>
<td style="width: 381.333px;">The number of open remediation tasks for the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.created</td>
<td style="width: 381.333px;">The timestamp of when the incident is created</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.lastUpdated</td>
<td style="width: 381.333px;">The timestamp of when the incident was last updated</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.lastUpdatedBy</td>
<td style="width: 381.333px;">The NetWitness user identifier of the user who last updated the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.assignee</td>
<td style="width: 381.333px;">The NetWitness user identifier of the user currently working on the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.sources</td>
<td style="width: 381.333px;">Unique set of sources for all alerts in the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.ruleId</td>
<td style="width: 381.333px;">The unique identifier of the rule that created the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.firstAlertTime</td>
<td style="width: 381.333px;">The timestamp of the earliest occurring alert in this incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.categories.id</td>
<td style="width: 381.333px;">The unique category identifier</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.categories.parent</td>
<td style="width: 381.333px;">Parent name of the category</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.categories.name</td>
<td style="width: 381.333px;">Friendly name of the category</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.journalEntries.id</td>
<td style="width: 381.333px;">The unique journal entry identifier</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.journalEntries.author</td>
<td style="width: 381.333px;">The author of this entry</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.journalEntries.notes</td>
<td style="width: 381.333px;">Notes and observations about the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.journalEntries.created</td>
<td style="width: 381.333px;">The timestamp of the journal entry created date</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.journalEntries.lastUpdated</td>
<td style="width: 381.333px;">The timestamp of the journal entry last updated date</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.journalEntries.milestone</td>
<td style="width: 381.333px;">Incident milestone classifier</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.createdBy</td>
<td style="width: 381.333px;">The NetWitness user ID or username of the rule that created the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.deletedAlertCount</td>
<td style="width: 381.333px;">The number of alerts that are deleted from the incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.eventCount</td>
<td style="width: 381.333px;">Number of events associated with incident</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.alertMeta.SourceIp</td>
<td style="width: 381.333px;">Unique source IP addresses</td>
</tr>
<tr>
<td style="width: 338.667px;">NetWitness.Incidents.alertMeta.DestinationIp</td>
<td style="width: 381.333px;">Unique destination IP addresses</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Examples</h5>
<pre>!NetWitness -get-incidents since=2018-01-01T14:00:00.000Z limit=200</pre>
<p> </p>
<pre>!NetWitness -get-incidents lastDays=4</pre>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Incidents<span class="pl-pds">"</span></span>: [
            {
                <span class="pl-s"><span class="pl-pds">"</span>alertCount<span class="pl-pds">"</span></span>: <span class="pl-c1">1</span>,
                <span class="pl-s"><span class="pl-pds">"</span>alertMeta<span class="pl-pds">"</span></span>: {
                    <span class="pl-s"><span class="pl-pds">"</span>DestinationIp<span class="pl-pds">"</span></span>: [
                        <span class="pl-s"><span class="pl-pds">"</span><span class="pl-pds">"</span></span>
                    ],
                    <span class="pl-s"><span class="pl-pds">"</span>SourceIp<span class="pl-pds">"</span></span>: [
                        <span class="pl-s"><span class="pl-pds">"</span><span class="pl-pds">"</span></span>
                    ]
                },
                <span class="pl-s"><span class="pl-pds">"</span>assignee<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                <span class="pl-s"><span class="pl-pds">"</span>averageAlertRiskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
                <span class="pl-s"><span class="pl-pds">"</span>categories<span class="pl-pds">"</span></span>: [],
                <span class="pl-s"><span class="pl-pds">"</span>created<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-03-29T13:55:55.644Z<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>createdBy<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>admin<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>deletedAlertCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
                <span class="pl-s"><span class="pl-pds">"</span>eventCount<span class="pl-pds">"</span></span>: <span class="pl-c1">2</span>,
                <span class="pl-s"><span class="pl-pds">"</span>firstAlertTime<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                <span class="pl-s"><span class="pl-pds">"</span>id<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>INC-23<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>journalEntries<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                <span class="pl-s"><span class="pl-pds">"</span>lastUpdated<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-03-29T13:55:55.644Z<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>lastUpdatedBy<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>admin<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>openRemediationTaskCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
                <span class="pl-s"><span class="pl-pds">"</span>priority<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Critical<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>riskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
                <span class="pl-s"><span class="pl-pds">"</span>ruleId<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                <span class="pl-s"><span class="pl-pds">"</span>sealed<span class="pl-pds">"</span></span>: <span class="pl-c1">false</span>,
                <span class="pl-s"><span class="pl-pds">"</span>sources<span class="pl-pds">"</span></span>: [
                    <span class="pl-s"><span class="pl-pds">"</span>NetWitness Investigate<span class="pl-pds">"</span></span>
                ],
                <span class="pl-s"><span class="pl-pds">"</span>status<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>New<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>summary<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>summary test <span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>title<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>test incident<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>totalRemediationTaskCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>
            },
            {
                <span class="pl-s"><span class="pl-pds">"</span>alertCount<span class="pl-pds">"</span></span>: <span class="pl-c1">1</span>,
                <span class="pl-s"><span class="pl-pds">"</span>alertMeta<span class="pl-pds">"</span></span>: {
                    <span class="pl-s"><span class="pl-pds">"</span>DestinationIp<span class="pl-pds">"</span></span>: [
                        <span class="pl-s"><span class="pl-pds">"</span>75.98.175.###<span class="pl-pds">"</span></span>
                    ],
                    <span class="pl-s"><span class="pl-pds">"</span>SourceIp<span class="pl-pds">"</span></span>: [
                        <span class="pl-s"><span class="pl-pds">"</span>192.168.11.###<span class="pl-pds">"</span></span>
                    ]
                },
                <span class="pl-s"><span class="pl-pds">"</span>assignee<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                <span class="pl-s"><span class="pl-pds">"</span>averageAlertRiskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
                <span class="pl-s"><span class="pl-pds">"</span>categories<span class="pl-pds">"</span></span>: [],
                <span class="pl-s"><span class="pl-pds">"</span>created<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-03-27T16:07:19.521Z<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>createdBy<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>admin<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>deletedAlertCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
                <span class="pl-s"><span class="pl-pds">"</span>eventCount<span class="pl-pds">"</span></span>: <span class="pl-c1">1</span>,
                <span class="pl-s"><span class="pl-pds">"</span>firstAlertTime<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                <span class="pl-s"><span class="pl-pds">"</span>id<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>INC-14<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>journalEntries<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                <span class="pl-s"><span class="pl-pds">"</span>lastUpdated<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-03-27T16:07:19.521Z<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>lastUpdatedBy<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>admin<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>openRemediationTaskCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
                <span class="pl-s"><span class="pl-pds">"</span>priority<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Critical<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>riskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
                <span class="pl-s"><span class="pl-pds">"</span>ruleId<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                <span class="pl-s"><span class="pl-pds">"</span>sealed<span class="pl-pds">"</span></span>: <span class="pl-c1">false</span>,
                <span class="pl-s"><span class="pl-pds">"</span>sources<span class="pl-pds">"</span></span>: [
                    <span class="pl-s"><span class="pl-pds">"</span>NetWitness Investigate<span class="pl-pds">"</span></span>
                ],
                <span class="pl-s"><span class="pl-pds">"</span>status<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>New<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>summary<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span><span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>title<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>log<span class="pl-pds">"</span></span>,
                <span class="pl-s"><span class="pl-pds">"</span>totalRemediationTaskCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>
            }
        ]
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h2>NetWitness Get Incidents</h2>
<h3>Incident Details</h3>
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Title</th>
<th>Summary</th>
<th>Risk score</th>
<th>Status</th>
<th>Alert count</th>
<th>Created</th>
<th>Last updated</th>
<th>Assignee</th>
<th>Sources</th>
<th>Categories</th>
</tr>
</thead>
<tbody>
<tr>
<td>INC-23</td>
<td>test incident</td>
<td>summary test</td>
<td>50</td>
<td>New</td>
<td>1</td>
<td>2018-03-29T13:55:55.644Z</td>
<td>2018-03-29T13:55:55.644Z</td>
<td> </td>
<td>NetWitness Investigate</td>
<td> </td>
</tr>
<tr>
<td>INC-22</td>
<td>test</td>
<td>blob</td>
<td>60</td>
<td>Assigned</td>
<td>1</td>
<td>2018-03-29T13:41:00.965Z</td>
<td>2018-07-12T13:54:47.194Z</td>
<td>admin</td>
<td>NetWitness Investigate</td>
<td>Physical:Connection</td>
</tr>
<tr>
<td>INC-21</td>
<td>User Behavior for test_user</td>
<td> </td>
<td>30</td>
<td>New</td>
<td>1</td>
<td>2018-03-28T19:27:48.521Z</td>
<td>2018-03-28T19:27:48.521Z</td>
<td> </td>
<td>Event Stream Analysis</td>
<td> </td>
</tr>
<tr>
<td>INC-20</td>
<td>ttyyy</td>
<td> </td>
<td>50</td>
<td>New</td>
<td>1</td>
<td>2018-03-27T16:16:01.899Z</td>
<td>2018-03-27T16:16:01.899Z</td>
<td> </td>
<td>NetWitness Investigate</td>
<td> </td>
</tr>
<tr>
<td>INC-19</td>
<td>test</td>
<td> </td>
<td>50</td>
<td>New</td>
<td>1</td>
<td>2018-03-27T16:15:50.027Z</td>
<td>2018-03-27T16:15:50.027Z</td>
<td> </td>
<td>NetWitness Investigate</td>
<td> </td>
</tr>
<tr>
<td>INC-18</td>
<td>log3</td>
<td> </td>
<td>50</td>
<td>New</td>
<td>1</td>
<td>2018-03-27T16:08:10.565Z</td>
<td>2018-03-27T16:08:10.565Z</td>
<td> </td>
<td>NetWitness Investigate</td>
<td> </td>
</tr>
<tr>
<td>INC-17</td>
<td>log4</td>
<td> </td>
<td>50</td>
<td>New</td>
<td>1</td>
<td>2018-03-27T16:07:55.403Z</td>
<td>2018-03-27T16:07:55.403Z</td>
<td> </td>
<td>NetWitness Investigate</td>
<td> </td>
</tr>
<tr>
<td>INC-16</td>
<td>log2</td>
<td> </td>
<td>50</td>
<td>New</td>
<td>1</td>
<td>2018-03-27T16:07:43.418Z</td>
<td>2018-03-27T16:07:43.418Z</td>
<td> </td>
<td>NetWitness Investigate</td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_2b24155b-c035-4450-9601-928a4778bbe9">3. Update an incident</h3>
<hr>
<p>Update a specific incident. Currently, an incident’s status and assignee may be modified</p>
<h5>Base Command</h5>
<p><code>netwitness-update-incident</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 166px;"><strong>Argument Name</strong></th>
<th style="width: 471px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 166px;">incidentId</td>
<td style="width: 471px;">The incident ID</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 166px;">status</td>
<td style="width: 471px;">The incident's current status</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">assignee</td>
<td style="width: 471px;">The NetWitness user identifier of the user currently working on the incident</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 284.667px;"><strong>Path</strong></th>
<th style="width: 435.333px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.id</td>
<td style="width: 435.333px;">The unique identifier of the incident.</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.title</td>
<td style="width: 435.333px;">Title of the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.summary</td>
<td style="width: 435.333px;">Summary of the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.priority</td>
<td style="width: 435.333px;">The incident priority</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.riskScore</td>
<td style="width: 435.333px;">Incident risk score calculated based on associated alert’s risk score. Risk score ranges from 0 (no risk) to 100 (highest risk).</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.status</td>
<td style="width: 435.333px;">The current status of the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.alertCount</td>
<td style="width: 435.333px;">Number of alerts associated with the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.averageAlertRiskScore</td>
<td style="width: 435.333px;">Average risk score of the alerts associated with the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.sealed</td>
<td style="width: 435.333px;">Indicates if additional alerts can be associated with an incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.totalRemediationTaskCount</td>
<td style="width: 435.333px;">The number of total remediation tasks for the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.openRemediationTaskCount</td>
<td style="width: 435.333px;">The number of open remediation tasks for the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.created</td>
<td style="width: 435.333px;">The timestamp of when the incident is created</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.lastUpdated</td>
<td style="width: 435.333px;">The timestamp of when the incident was last updated</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.lastUpdatedBy</td>
<td style="width: 435.333px;">The NetWitness user identifier of the user who last updated the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.assignee</td>
<td style="width: 435.333px;">The NetWitness user identifier of the user currently working on the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.sources</td>
<td style="width: 435.333px;">Unique set of sources for all alerts in the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.ruleId</td>
<td style="width: 435.333px;">The unique identifier of the rule that created the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.firstAlertTime</td>
<td style="width: 435.333px;">The timestamp of the earliest occurring alert in this incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.categories.id</td>
<td style="width: 435.333px;">The unique category identifier</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.categories.parent</td>
<td style="width: 435.333px;">Parent name of the category</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.categories.name</td>
<td style="width: 435.333px;">Friendly name of the category</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.journalEntries.id</td>
<td style="width: 435.333px;">The unique journal entry identifier</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.journalEntries.author</td>
<td style="width: 435.333px;">The author of this entry</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.journalEntries.notes</td>
<td style="width: 435.333px;">Notes and observations about the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.journalEntries.created</td>
<td style="width: 435.333px;">The timestamp of the journal entry created date</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.journalEntries.lastUpdated</td>
<td style="width: 435.333px;">The timestamp of the journal entry last updated date</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.journalEntries.milestone</td>
<td style="width: 435.333px;">Incident milestone classifier</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.createdBy</td>
<td style="width: 435.333px;">The NetWitness user ID or username of the rule that created the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.deletedAlertCount</td>
<td style="width: 435.333px;">The number of alerts that are deleted from the incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.eventCount</td>
<td style="width: 435.333px;">Number of events associated with incident</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.alertMeta.SourceIp</td>
<td style="width: 435.333px;">Unique source IP addresses</td>
</tr>
<tr>
<td style="width: 284.667px;">NetWitness.Incidents.alertMeta.DestinationIp</td>
<td style="width: 435.333px;">Unique destination IP addresses</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!netwitness-update-incident incidentId=INC-12 status=InProgress</pre>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Incidents<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>alertCount<span class="pl-pds">"</span></span>: <span class="pl-c1">1</span>,
            <span class="pl-s"><span class="pl-pds">"</span>alertMeta<span class="pl-pds">"</span></span>: {
                <span class="pl-s"><span class="pl-pds">"</span>DestinationIp<span class="pl-pds">"</span></span>: [
                    <span class="pl-s"><span class="pl-pds">"</span>192.168.5.172<span class="pl-pds">"</span></span>
                ],
                <span class="pl-s"><span class="pl-pds">"</span>SourceIp<span class="pl-pds">"</span></span>: [
                    <span class="pl-s"><span class="pl-pds">"</span>192.168.5.189<span class="pl-pds">"</span></span>
                ]
            },
            <span class="pl-s"><span class="pl-pds">"</span>assignee<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>averageAlertRiskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
            <span class="pl-s"><span class="pl-pds">"</span>categories<span class="pl-pds">"</span></span>: [],
            <span class="pl-s"><span class="pl-pds">"</span>created<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-03-15T16:39:18.802Z<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>createdBy<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>admin<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>deletedAlertCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
            <span class="pl-s"><span class="pl-pds">"</span>eventCount<span class="pl-pds">"</span></span>: <span class="pl-c1">1</span>,
            <span class="pl-s"><span class="pl-pds">"</span>firstAlertTime<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>id<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>INC-12<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>journalEntries<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>lastUpdated<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-08-28T16:18:20.858Z<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>lastUpdatedBy<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>admin<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>openRemediationTaskCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
            <span class="pl-s"><span class="pl-pds">"</span>priority<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Medium<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>riskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
            <span class="pl-s"><span class="pl-pds">"</span>ruleId<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>sealed<span class="pl-pds">"</span></span>: <span class="pl-c1">true</span>,
            <span class="pl-s"><span class="pl-pds">"</span>sources<span class="pl-pds">"</span></span>: [
                <span class="pl-s"><span class="pl-pds">"</span>NetWitness Investigate<span class="pl-pds">"</span></span>
            ],
            <span class="pl-s"><span class="pl-pds">"</span>status<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>InProgress<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>summary<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span><span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>title<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Network Alert1<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>totalRemediationTaskCount<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>
        }
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h2>NetWitness Update Incident</h2>
<h3>Incident Details</h3>
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Title</th>
<th>Summary</th>
<th>Risk score</th>
<th>Status</th>
<th>Alert count</th>
<th>Created</th>
<th>Last updated</th>
<th>Assignee</th>
<th>Sources</th>
<th>Categories</th>
</tr>
</thead>
<tbody>
<tr>
<td>INC-12</td>
<td>Network Alert1</td>
<td> </td>
<td>50</td>
<td>InProgress</td>
<td>1</td>
<td>2018-03-15T16:39:18.802Z</td>
<td>2018-08-28T16:18:20.858Z</td>
<td> </td>
<td>NetWitness Investigate</td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_42f04935-4255-4322-afa7-1d8486afb65c">4. Delete an incident</h3>
<hr>
<p>Delete a specific incident, according to the incident ID.</p>
<h5>Base Command</h5>
<p><code>netwitness-delete-incident</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 282px;"><strong>Argument Name</strong></th>
<th style="width: 257px;"><strong>Description</strong></th>
<th style="width: 169px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 282px;">incidentId</td>
<td style="width: 257px;">The incident ID</td>
<td style="width: 169px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!netwitness-delete-incident incidentId=INC-12</pre>
<h3 id="h_ea23ce95-17e1-4395-84f9-422c83f30955">5. Get all alerts for an incident</h3>
<hr>
<p>Get all the alerts related to a specific incident.</p>
<h5>Base Command</h5>
<p><code>netwitness-get-alerts</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 274px;"><strong>Argument Name</strong></th>
<th style="width: 265px;"><strong>Description</strong></th>
<th style="width: 169px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 274px;">incidentId</td>
<td style="width: 265px;">The incident ID</td>
<td style="width: 169px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 404.667px;"><strong>Path</strong></th>
<th style="width: 315.333px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.id</td>
<td style="width: 315.333px;">The unique alert identifier</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.incidentId</td>
<td style="width: 315.333px;">The incident ID associated with the alert</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.title</td>
<td style="width: 315.333px;">The title or name of the rule that created the alert</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.detail</td>
<td style="width: 315.333px;">The details of the alert. This can be the module name or meta that the module included.</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.created</td>
<td style="width: 315.333px;">The timestamp of the alert created date</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.source</td>
<td style="width: 315.333px;">The source of this alert. For example, "Event Stream Analysis", "Malware Analysis", and so on.</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.riskScore</td>
<td style="width: 315.333px;">The risk score of this alert, usually in the range 0 - 100.</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.type</td>
<td style="width: 315.333px;">Type of alert (Network, Log, and so on)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.source.device.ipAddress</td>
<td style="width: 315.333px;">The source IP address</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.source.device.port</td>
<td style="width: 315.333px;">The source port</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.source.device.macAddress</td>
<td style="width: 315.333px;">The source Ethernet MAC address</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.source.device.dnsHostname</td>
<td style="width: 315.333px;">The source DNS resolved hostname</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.source.device.dnsDomain</td>
<td style="width: 315.333px;">The top-level domain from the DNS resolved hostname (source)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.source.user.username</td>
<td style="width: 315.333px;">The unique username (source)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.source.user.emailAddress</td>
<td style="width: 315.333px;">An email address (source)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.source.user.adUsername</td>
<td style="width: 315.333px;">An Active Directory (AD) username (source)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.source.user.adDomain</td>
<td style="width: 315.333px;">An Active Directory (AD) domain (source)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.destination.device.ipAddress</td>
<td style="width: 315.333px;">The destination IP address</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.destination.device.port</td>
<td style="width: 315.333px;">The destination port</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.destination.device.macAddress</td>
<td style="width: 315.333px;">The destination Ethernet MAC address </td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.destination.device.dnsHostname</td>
<td style="width: 315.333px;">The destination DNS resolved hostname</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.destination.device.dnsDomain</td>
<td style="width: 315.333px;">The top-level domain from the DNS resolved hostname (destination)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.destination.user.username</td>
<td style="width: 315.333px;">The unique username (destination)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.destination.user.emailAddress</td>
<td style="width: 315.333px;">An email address (destination)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.destination.user.adUsername</td>
<td style="width: 315.333px;">An Active Directory (AD) username (destination)</td>
</tr>
<tr>
<td style="width: 404.667px;">NetWitness.Alerts.events.destination.user.adDomain</td>
<td style="width: 315.333px;">An Active Directory (AD) domain (destination)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!netwitness-get-alerts incidentId="INC-12"</pre>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Alerts<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>created<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-03-15T16:39:18.777Z<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>detail<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
            <span class="pl-s"><span class="pl-pds">"</span>events<span class="pl-pds">"</span></span>: [
                {
                    <span class="pl-s"><span class="pl-pds">"</span>destination<span class="pl-pds">"</span></span>: {
                        <span class="pl-s"><span class="pl-pds">"</span>device<span class="pl-pds">"</span></span>: {
                            <span class="pl-s"><span class="pl-pds">"</span>dnsDomain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>dnsHostname<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>ipAddress<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>192.168.5.172<span class="pl-pds">"</span></span>,
                            <span class="pl-s"><span class="pl-pds">"</span>macAddress<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>00:0C:29:62:29:43<span class="pl-pds">"</span></span>,
                            <span class="pl-s"><span class="pl-pds">"</span>port<span class="pl-pds">"</span></span>: <span class="pl-c1">23</span>
                        },
                        <span class="pl-s"><span class="pl-pds">"</span>user<span class="pl-pds">"</span></span>: {
                            <span class="pl-s"><span class="pl-pds">"</span>adDomain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>adUsername<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>emailAddress<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>username<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>administrator<span class="pl-pds">"</span></span>
                        }
                    },
                    <span class="pl-s"><span class="pl-pds">"</span>domain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                    <span class="pl-s"><span class="pl-pds">"</span>eventSource<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                    <span class="pl-s"><span class="pl-pds">"</span>eventSourceId<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>7<span class="pl-pds">"</span></span>,
                    <span class="pl-s"><span class="pl-pds">"</span>source<span class="pl-pds">"</span></span>: {
                        <span class="pl-s"><span class="pl-pds">"</span>device<span class="pl-pds">"</span></span>: {
                            <span class="pl-s"><span class="pl-pds">"</span>dnsDomain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>dnsHostname<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>ipAddress<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>192.168.5.189<span class="pl-pds">"</span></span>,
                            <span class="pl-s"><span class="pl-pds">"</span>macAddress<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>00:0C:29:D1:39:5D<span class="pl-pds">"</span></span>,
                            <span class="pl-s"><span class="pl-pds">"</span>port<span class="pl-pds">"</span></span>: <span class="pl-c1">1045</span>
                        },
                        <span class="pl-s"><span class="pl-pds">"</span>user<span class="pl-pds">"</span></span>: {
                            <span class="pl-s"><span class="pl-pds">"</span>adDomain<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>adUsername<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>emailAddress<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
                            <span class="pl-s"><span class="pl-pds">"</span>username<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>administrator<span class="pl-pds">"</span></span>
                        }
                    }
                }
            ],
            <span class="pl-s"><span class="pl-pds">"</span>id<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>5aaaa1b69a95133336911c93<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>incidentId<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>INC-12<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>riskScore<span class="pl-pds">"</span></span>: <span class="pl-c1">50</span>,
            <span class="pl-s"><span class="pl-pds">"</span>source<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>NetWitness Investigate<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>title<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Network Alert1<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>type<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Network<span class="pl-pds">"</span></span>
        }
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h2>Incident INC-12 Alerts</h2>
<h3>Alert Details</h3>
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Title</th>
<th>Detail</th>
<th>Created</th>
<th>Source</th>
<th>Risk score</th>
<th>Type</th>
<th>Total events</th>
</tr>
</thead>
<tbody>
<tr>
<td>5aaaa1b69a95133336911c93</td>
<td>Network Alert1</td>
<td> </td>
<td>2018-03-15T16:39:18.777Z</td>
<td>NetWitness Investigate</td>
<td>50</td>
<td>Network</td>
<td>1</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Event Details</h3>
<p><em>Domain:</em> None<br> <em>Source:</em> None<br> <em>ID:</em> 7</p>
<h3>Source</h3>
<table style="width: 748px;" border="2">
<thead>
<tr>
<th style="width: 161.333px;">Device IP</th>
<th style="width: 149.667px;">Device Port</th>
<th style="width: 228px;">Device MAC</th>
<th style="width: 195px;">User UserName</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161.333px;">192.168.5.189</td>
<td style="width: 149.667px;">1045</td>
<td style="width: 228px;">00:0C:29:D1:39:5D</td>
<td style="width: 195px;">administrator</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Destination</h3>
<table style="width: 748px;" border="2">
<thead>
<tr>
<th style="width: 162.667px;">Device IP</th>
<th style="width: 151.333px;">Device Port</th>
<th style="width: 224px;">Device MAC</th>
<th style="width: 196px;">User UserName</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162.667px;">192.168.5.172</td>
<td style="width: 151.333px;">23</td>
<td style="width: 224px;">00:0C:29:62:29:43</td>
<td style="width: 196px;">administrator</td>
</tr>
</tbody>
</table>
<p> </p>
<h2>Additional Information</h2>
<hr>
<h4>Incidents query with time frame restriction</h4>
<p>The time frame can be restricted on only one end, specifying <em>since</em> or <em>until</em> arguments, or restricted on both ends, specifying both arguments.</p>
<p>Both arguments should be passed in ISO 8601 format:</p>
<p>!NetWitness-get-incidents since=2018-01-01T14:00:00.000Z<br> until=2018-01-01T16:30:00.000Z</p>
<p>In this example, all incidents created between 2:00 PM on January 1, 2018 and 2:30 PM<br> the same day will be fetched.</p>
<p>Another option is to specify the number of days prior as a time frame:</p>
<p>!NetWitness-get-incidents lastDays=10</p>
<p>In this example, all incidents created in the 10 days prior to the current date will be fetched.</p>
<h2>Known Limitations</h2>
<hr>
<ul>
<li>Only an incident’s status and assignee fields can be modified.</li>
<li>Incidents query can only be filtered using by time frame.</li>
</ul>
<h2>Troubleshooting</h2>
<hr>
<ul>
<li>
<p><strong>‘Request failed with status: 400..’</strong> error when running a NetWitness command<br> If this error raises, it indicates one of the arguments passed is not a valid value.<br> For example:</p>
<ul>
<li>Passing non-existing incident id to ‘get-incidents’ will cause this type of error.</li>
<li>Passing invalid timestamp to ‘NetWitness-get-incidents’ will cause this type of error.<br> The error message provides a short description of the problem.</li>
</ul>
<p>Error snap-shot</p>
</li>
<li>
<p><strong>‘Login failed with status: 401..’</strong> when testing instance configuration<br> This error indicates bad credentials are configured in the instance settings.<br> Make sure correct credentials and password is configured in the instance settings.</p>
<p>Error snap-shot</p>
</li>
<li>
<p><strong>‘…CERTIFICATE_VERIFY_FAILED...’</strong> error when testing instance configuration<br> This error may indicate that server certificate is missing/cannot be validated.<br> It is possible to bypass certificate validation by checking ‘Do not validate server certificate’ in the instance settings.</p>
</li>
</ul>
