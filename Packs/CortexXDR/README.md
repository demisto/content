<p>
  Cortex XDR is the world's first detection and response app that natively integrates
  network, endpoint and cloud data to stop sophisticated attacks.
</p>
<h2>Automation</h2>
<p>
  <span>To sync incidents between Demisto and Cortex XDR, you should use the <code>XDRSyncScript</code> script, which you can find in the automation page.</span>
</p>
<h2>Use Cases</h2>
<ol>
  <li>Fetch incidents from XDR</li>
  <li>Get a list of incidents from XDR</li>
  <li>Update incident in XDR</li>
</ol>
<h2>
  Configure Palo Alto Networks Cortex XDR - Investigation and Response on Demisto
</h2>
<p>
  You need to collect several pieces of information in order to configure the integration
  on Demisto.
</p>
<h3>Generate an API Key and API Key ID</h3>
<ol>
  <li>
    In your Cortex XDR platform, go to<span>&nbsp;</span><strong>Settings</strong>.
  </li>
  <li>
    Click the<span>&nbsp;</span><strong>+New Key</strong><span>&nbsp;</span>button
    in the top right corner
  </li>
  <li>
    Generate a key of type<span>&nbsp;</span><strong>Advanced</strong>.
  </li>
  <li>Copy and paste the key.</li>
  <li>From the ID column, copy the Key ID.</li>
</ol>
<h3>URL</h3>
<ol>
  <li>
    In your Cortex XDR platform, go to<span>&nbsp;</span><strong>Settings</strong>.
  </li>
  <li>
    Click the<span>&nbsp;</span><strong>Copy URL</strong><span>&nbsp;</span>button
    in the top right corner.
  </li>
</ol>
<h3>Configure integration parameters</h3>
<ol>
  <li>
    Navigate to<span>&nbsp;</span><strong>Settings</strong><span>&nbsp;</span>&gt;<span>&nbsp;</span><strong>Integrations</strong><span>&nbsp;</span>&gt;<span>&nbsp;</span><strong>Servers &amp; Services</strong>.
  </li>
  <li>
    Search for Palo Alto Networks Cortex XDR - Investigation and Response .
  </li>
  <li>
    Click<span>&nbsp;</span><strong>Add instance</strong><span>&nbsp;</span>to
    create and configure a new integration instance.
    <ul>
      <li>
        <strong>Name</strong>: a textual name for the integration instance.
      </li>
      <li>
        <strong>Fetch incidents</strong>
      </li>
      <li>
        <strong>Incident type</strong>
      </li>
      <li>
        <strong>Server URL (copy url from XDR - press ? to see more info)</strong>
      </li>
      <li>
        <strong>API Key ID</strong>
      </li>
      <li>
        <strong>API Key</strong>
      </li>
      <li>
        <strong>Trust any certificate (insecure)</strong>
      </li>
      <li>
        <strong>Use system proxy</strong>
      </li>
      <li>
        <strong>First fetch timestamp ( , e.g., 12 hours, 7 days)</strong>
      </li>
    </ul>
  </li>
  <li>
    Click<span>&nbsp;</span><strong>Test</strong><span>&nbsp;</span>to validate
    the URLs, token, and connection.
  </li>
</ol>
<h2>Fetched Incidents Data</h2>
<pre>incident_id:31
creation_time:1564594008755
modification_time:1566339537617
detection_time:null
status:new
severity:low
description:6 'Microsoft Windows RPC Fragment Evasion Attempt' alerts detected by PAN NGFW on 6 hosts
assigned_user_mail:null
assigned_user_pretty_name:null
alert_count:6
low_severity_alert_count:0
med_severity_alert_count:6
high_severity_alert_count:0
user_count:1
host_count:6
notes:null
resolve_comment:null
manual_severity:low
manual_description:null
xdr_url:https://1111.paloaltonetworks.com/incident-view/31
</pre>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation,
  or in a playbook.<br>
  After you successfully execute a command, a DBot message appears in the War Room
  with the command details.
</p>
<ol>
  <li>
    <a href="#h_516ee3ab-758c-4c54-930d-d6f2ea76a577" target="_self">Get a list of incidents: xdr-get-incidents</a>
  </li>
  <li>
    <a href="#h_5d044c35-76e5-4ee1-aebb-329146968c93" target="_self">Get extra data for an incident: xdr-get-incident-extra-data</a>
  </li>
  <li>
    <a href="#h_2044c2ca-8897-4439-9623-e3d25248df47" target="_self">Update an incident: xdr-update-incident</a>
  </li>
</ol>
<h3 id="h_516ee3ab-758c-4c54-930d-d6f2ea76a577">1. Get a list of incidents</h3>
<hr>
<p>
  Returns a list of incidents, which you can filter by a list of incident IDs (max
  100), the time the incident was last modified, and the time the incident was
  created.&nbsp;If you pass multiple filtering arguments, they will be concatenated
  using the AND condition. The OR condition is not supported.
</p>
<h5>Base Command</h5>
<p>
  <code>xdr-get-incidents</code>
</p>
<h5>Input</h5>
<table style="width:749px">
  <thead>
    <tr>
      <th style="width:193px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:476px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:193px">lte_creation_time</td>
      <td style="width:476px">Time format 2019-12-31T23:59:00.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">gte_creation_time</td>
      <td style="width:476px">
        Returned incidents that were created on or after the specified date/time,
        in the format 2019-12-31T23:59:00.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">lte_modification_time</td>
      <td style="width:476px">
        Filters returned incidents that were created on or before the specified
        date/time, in the format 2019-12-31T23:59:00.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">gte_modification_time</td>
      <td style="width:476px">
        Filters returned incidents that were modified on or after the specified
        date/time, in the format 2019-12-31T23:59:00.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">incident_id_list</td>
      <td style="width:476px">An array or CSV string of incident IDs.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">since_creation_time</td>
      <td style="width:476px">
        Filters returned incidents that were created on or after the specified
        date/time range, for example, 1 month, 2 days, 1 hour, and so on.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">since_modification_time</td>
      <td style="width:476px">
        Filters returned incidents that were modified on or after the specified
        date/time range, for example, 1 month, 2 days, 1 hour, and so on.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">sort_by_modification_time</td>
      <td style="width:476px">
        Sorts returned incidents by the date/time that the incident was last
        modified ("asc" - ascending, "desc" - descending).
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">sort_by_creation_time</td>
      <td style="width:476px">
        Sorts returned incidents by the date/time that the incident was created
        ("asc" - ascending, "desc" - descending).
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">page</td>
      <td style="width:476px">
        Page number (for pagination). The default is 0 (the first page).
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:193px">limit</td>
      <td style="width:476px">
        Maximum number of incidents to return per page. The default and maximum
        is 100.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:749px">
  <thead>
    <tr>
      <th style="width:423px">
        <strong>Path</strong>
      </th>
      <th style="width:52px">
        <strong>Type</strong>
      </th>
      <th style="width:265px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.incident_id</td>
      <td style="width:52px">String</td>
      <td style="width:265px">Unique ID assigned to each returned incident.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.manual_severity</td>
      <td style="width:52px">String</td>
      <td style="width:265px">
        Incident severity assigned by the user. This does not affect the
        calculated severity (LOW, MEDIUM, HIGH).
      </td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.manual_description</td>
      <td style="width:52px">String</td>
      <td style="width:265px">Incident description provided by the user.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.assigned_user_mail</td>
      <td style="width:52px">String</td>
      <td style="width:265px">Email address of the assigned user.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.high_severity_alert_count</td>
      <td style="width:52px">String</td>
      <td style="width:265px">Number of alerts with the severity HIGH.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.host_count</td>
      <td style="width:52px">number</td>
      <td style="width:265px">Number of hosts involved in the incident.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.xdr_url</td>
      <td style="width:52px">String</td>
      <td style="width:265px">A link to the incident view on XDR.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.assigned_user_pretty_name</td>
      <td style="width:52px">String</td>
      <td style="width:265px">Full name of the user assigned to the incident.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.alert_count</td>
      <td style="width:52px">number</td>
      <td style="width:265px">Total number of alerts in the incident.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.med_severity_alert_count</td>
      <td style="width:52px">number</td>
      <td style="width:265px">Number of alerts with the severity MEDIUM.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.user_count</td>
      <td style="width:52px">number</td>
      <td style="width:265px">Number of users involved in the incident.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.severity</td>
      <td style="width:52px">String</td>
      <td style="width:265px">Calculated severity of the incident (LOW, MEDIUM, HIGH).</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.low_severity_alert_count</td>
      <td style="width:52px">String</td>
      <td style="width:265px">Number of alerts with the severity LOW.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.status</td>
      <td style="width:52px">String</td>
      <td style="width:265px">
        Current status of the incident (NEW, UNDER_INVESTIGATION, RESOLVED_THREAT_HANDLED,
        RESOLVED_KNOWN_ISSUE, RESOLVED_DUPLICATE, RESOLVED_FALSE_POSITIVE,
        RESOLVED_OTHER).
      </td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.description</td>
      <td style="width:52px">String</td>
      <td style="width:265px">Dynamic calculated description of the incident.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.resolve_comment</td>
      <td style="width:52px">String</td>
      <td style="width:265px">
        Comments entered by the user when the incident was resolved.
      </td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.notes</td>
      <td style="width:52px">String</td>
      <td style="width:265px">Comments entered by the user regarding the incident.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.creation_time</td>
      <td style="width:52px">date</td>
      <td style="width:265px">Date and time the incident was created on XDR.</td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.detection_time</td>
      <td style="width:52px">date</td>
      <td style="width:265px">
        Date and time that the first alert occurred in the incident.
      </td>
    </tr>
    <tr>
      <td style="width:423px">PaloAltoNetworksXDR.Incident.modification_time</td>
      <td style="width:52px">date</td>
      <td style="width:265px">Date and time that the incident was last modified.</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Examples</h5>
<pre>!xdr-get-incidents incident_id_list="30,12,33"</pre>
<pre>!xdr-get-incidents since_creation_time="3 month" sort_by_creation_time="asc" page="0" limit="3"</pre>
<h5>Context Example</h5>
<pre>{
    "PaloAltoNetworksXDR.Incident": [
        {
            "host_count": 6, 
            "incident_id": "1", 
            "manual_severity": null, 
            "description": "'SMB: User Password Brute Force Attempt' along with 8 other alerts generated by PAN NGFW detected on 6 hosts", 
            "severity": "high", 
            "modification_time": 1566994926897, 
            "assigned_user_pretty_name": "Michael Foo", 
            "notes": null, 
            "creation_time": 1564423080364, 
            "alert_count": 9, 
            "med_severity_alert_count": 5, 
            "detection_time": null, 
            "assigned_user_mail": "foo@demisto.com", 
            "resolve_comment": "some comment", 
            "status": "resolved_false_positive", 
            "user_count": 1, 
            "xdr_url": "https://1111.paloaltonetworks.com/incident-view/1", 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 4, 
            "manual_description": null
        }, 
        {
            "host_count": 1, 
            "incident_id": "2", 
            "manual_severity": null, 
            "description": "7 'SIP INVITE Method Request Flood Attempt' alerts detected by PAN NGFW on host 10.54.12.6 ", 
            "severity": "high", 
            "modification_time": 1565263085359, 
            "assigned_user_pretty_name": "Michael Foo", 
            "notes": null, 
            "creation_time": 1564424187325, 
            "alert_count": 7, 
            "med_severity_alert_count": 0, 
            "detection_time": null, 
            "assigned_user_mail": "foo@demisto.com", 
            "resolve_comment": "Possible white list and FP", 
            "status": "resolved_other", 
            "user_count": 1, 
            "xdr_url": "https://1111.paloaltonetworks.com/incident-view/2", 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 7, 
            "manual_description": null
        }, 
        {
            "host_count": 7, 
            "incident_id": "3", 
            "manual_severity": null, 
            "description": "'HTTP Unauthorized Brute Force Attack' along with 25 other alerts generated by PAN NGFW detected on 7 hosts", 
            "severity": "high", 
            "modification_time": 1566812108905, 
            "assigned_user_pretty_name": "Michael Foo", 
            "notes": null, 
            "creation_time": 1564424454867, 
            "alert_count": 26, 
            "med_severity_alert_count": 0, 
            "detection_time": null, 
            "assigned_user_mail": "foo@demisto.com", 
            "resolve_comment": null, 
            "status": "new", 
            "user_count": 1, 
            "xdr_url": "https://1111.paloaltonetworks.com/incident-view/3", 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 26, 
            "manual_description": null
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Incidents</h3>
<table>
  <thead>
    <tr>
      <th>alert_count</th>
      <th>assigned_user_mail</th>
      <th>assigned_user_pretty_name</th>
      <th>creation_time</th>
      <th>description</th>
      <th>detection_time</th>
      <th>high_severity_alert_count</th>
      <th>host_count</th>
      <th>incident_id</th>
      <th>low_severity_alert_count</th>
      <th>manual_description</th>
      <th>manual_severity</th>
      <th>med_severity_alert_count</th>
      <th>modification_time</th>
      <th>notes</th>
      <th>resolve_comment</th>
      <th>severity</th>
      <th>status</th>
      <th>user_count</th>
      <th>xdr_url</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>9</td>
      <td>foo@demisto.com</td>
      <td>Michael Foo</td>
      <td>1564423080364</td>
      <td>
        'SMB: User Password Brute Force Attempt' along with 8 other alerts
        generated by PAN NGFW detected on 6 hosts
      </td>
      <td>&nbsp;</td>
      <td>4</td>
      <td>6</td>
      <td>1</td>
      <td>0</td>
      <td>&nbsp;</td>
      <td>&nbsp;</td>
      <td>5</td>
      <td>1566994926897</td>
      <td>&nbsp;</td>
      <td>some comment</td>
      <td>high</td>
      <td>resolved_false_positive</td>
      <td>1</td>
      <td>
        <a href="https://1111.paloaltonetworks.com/incident-view/1" rel="nofollow">https://1111.paloaltonetworks.com/incident-view/1</a>
      </td>
    </tr>
    <tr>
      <td>7</td>
      <td>foo@demisto.com</td>
      <td>Michael Foo</td>
      <td>1564424187325</td>
      <td>
        7 'SIP INVITE Method Request Flood Attempt' alerts detected by PAN
        NGFW on host 10.54.12.6
      </td>
      <td>&nbsp;</td>
      <td>7</td>
      <td>1</td>
      <td>2</td>
      <td>0</td>
      <td>&nbsp;</td>
      <td>&nbsp;</td>
      <td>0</td>
      <td>1565263085359</td>
      <td>&nbsp;</td>
      <td>Possible white list and FP</td>
      <td>high</td>
      <td>resolved_other</td>
      <td>1</td>
      <td>
        <a href="https://1111.paloaltonetworks.com/incident-view/2" rel="nofollow">https://1111.paloaltonetworks.com/incident-view/2</a>
      </td>
    </tr>
    <tr>
      <td>26</td>
      <td>foo@demisto.com</td>
      <td>Michael Foo</td>
      <td>1564424454867</td>
      <td>
        'HTTP Unauthorized Brute Force Attack' along with 25 other alerts
        generated by PAN NGFW detected on 7 hosts
      </td>
      <td>&nbsp;</td>
      <td>26</td>
      <td>7</td>
      <td>3</td>
      <td>0</td>
      <td>&nbsp;</td>
      <td>&nbsp;</td>
      <td>0</td>
      <td>1566812108905</td>
      <td>&nbsp;</td>
      <td>&nbsp;</td>
      <td>high</td>
      <td>new</td>
      <td>1</td>
      <td>
        <a href="https://1111.paloaltonetworks.com/incident-view/3" rel="nofollow">https://1111.paloaltonetworks.com/incident-view/3</a>
      </td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_5d044c35-76e5-4ee1-aebb-329146968c93">2. Get extra data for an incident</h3>
<hr>
<p>
  Returns additional data for the specified incident, for example, related alerts,
  file artifacts, network artifacts, and so on.
</p>
<h5>Required Permissions</h5>
<p>
  <strong>FILL IN REQUIRED PERMISSIONS HERE</strong>
</p>
<h5>Base Command</h5>
<p>
  <code>xdr-get-incident-extra-data</code>
</p>
<h5>Input</h5>
<table style="width:749px">
  <thead>
    <tr>
      <th style="width:170px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:479px">
        <strong>Description</strong>
      </th>
      <th style="width:91px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:170px">incident_id</td>
      <td style="width:479px">The ID of the incident for which to get additional data.</td>
      <td style="width:91px">Required</td>
    </tr>
    <tr>
      <td style="width:170px">alerts_limit</td>
      <td style="width:479px">Maximum number of alerts to return. Default is 1,000.</td>
      <td style="width:91px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:789px">
  <thead>
    <tr>
      <th style="width:514px">
        <strong>Path</strong>
      </th>
      <th style="width:44px">
        <strong>Type</strong>
      </th>
      <th style="width:222px">
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.incident_id</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Unique ID assigned to each returned incident.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.manual_severity</td>
      <td style="width:44px">String</td>
      <td style="width:222px">
        Incident severity assigned by the user. This does not affect the
        calculated severity (LOW, MEDIUM, HIGH).
      </td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.manual_description</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Incident description provided by the user.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.assigned_user_mail</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Email address of the assigned user.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.high_severity_alert_count</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Number of alerts with the severity HIGH.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.host_count</td>
      <td style="width:44px">number</td>
      <td style="width:222px">Number of hosts involved in the incident</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.xdr_url</td>
      <td style="width:44px">String</td>
      <td style="width:222px">A link to the incident view on XDR.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.assigned_user_pretty_name</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Full name of the user assigned to the incident.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alert_count</td>
      <td style="width:44px">number</td>
      <td style="width:222px">Total number of alerts in the incident.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.med_severity_alert_count</td>
      <td style="width:44px">number</td>
      <td style="width:222px">Number of alerts with the severity MEDIUM.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.user_count</td>
      <td style="width:44px">number</td>
      <td style="width:222px">Number of users involved in the incident.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.severity</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Calculated severity of the incident (LOW, MEDIUM, HIGH).</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.low_severity_alert_count</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Number of alerts with the severity LOW.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.status</td>
      <td style="width:44px">String</td>
      <td style="width:222px">
        Current status of the incident (NEW, UNDER_INVESTIGATION, RESOLVED_THREAT_HANDLED,
        RESOLVED_KNOWN_ISSUE, RESOLVED_DUPLICATE, RESOLVED_FALSE_POSITIVE,
        RESOLVED_OTHER).
      </td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.description</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Dynamic calculated description of the incident.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.resolve_comment</td>
      <td style="width:44px">String</td>
      <td style="width:222px">
        Comments entered by the user when the incident was resolved.
      </td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.notes</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Comments entered by the user regarding the incident.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.creation_time</td>
      <td style="width:44px">date</td>
      <td style="width:222px">Date and time the incident was created on XDR.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.detection_time</td>
      <td style="width:44px">date</td>
      <td style="width:222px">
        Date and time that the first alert occurred in the incident.
      </td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.modification_time</td>
      <td style="width:44px">date</td>
      <td style="width:222px">Date and time that the incident was last modified.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.category</td>
      <td style="width:44px">String</td>
      <td style="width:222px">
        Category of the alert, for example, Spyware Detected via Anti-Spyware
        profile.
      </td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.action_pretty</td>
      <td style="width:44px">String</td>
      <td style="width:222px">The action that triggered the alert.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.description</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Textual description of the alert.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.severity</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Severity of the alert.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.host_ip</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Host IP involved in the alert.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.source</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Source of the alert.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.user_name</td>
      <td style="width:44px">String</td>
      <td style="width:222px">User name involved with the alert.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.alert_id</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Unique ID for each alert.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.host_name</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Host name involved in the alert.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.detection_timestamp</td>
      <td style="width:44px">date</td>
      <td style="width:222px">Date and time that the alert occurred.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.alerts.name</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Calculated name of the alert.</td>
    </tr>
    <tr>
      <td style="width:514px">
        PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_port
      </td>
      <td style="width:44px">number</td>
      <td style="width:222px">The remote port related to the artifact.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.network_artifacts.alert_count</td>
      <td style="width:44px">number</td>
      <td style="width:222px">Number of alerts related to the artifact.</td>
    </tr>
    <tr>
      <td style="width:514px">
        PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_ip
      </td>
      <td style="width:44px">String</td>
      <td style="width:222px">The remote IP related to the artifact.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.network_artifacts.is_manual</td>
      <td style="width:44px">boolean</td>
      <td style="width:222px">Whether the artifact was created by the user (manually).</td>
    </tr>
    <tr>
      <td style="width:514px">
        PaloAltoNetworksXDR.Incident.network_artifacts.network_domain
      </td>
      <td style="width:44px">String</td>
      <td style="width:222px">The domain related to the artifact.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.network_artifacts.type</td>
      <td style="width:44px">String</td>
      <td style="width:222px">The artifact type, for example, IP.</td>
    </tr>
    <tr>
      <td style="width:514px">
        PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_status
      </td>
      <td style="width:44px">String</td>
      <td style="width:222px">Digital signature status of the file.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.file_artifacts.is_process</td>
      <td style="width:44px">boolean</td>
      <td style="width:222px">
        Whether the file artifact is related to a process execution.
      </td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.file_artifacts.file_name</td>
      <td style="width:44px">String</td>
      <td style="width:222px">Name of the file.</td>
    </tr>
    <tr>
      <td style="width:514px">
        PaloAltoNetworksXDR.Incident.file_artifacts.file_wildfire_verdict
      </td>
      <td style="width:44px">String</td>
      <td style="width:222px">The file verdict, calculated by Wildfire.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.file_artifacts.alert_count</td>
      <td style="width:44px">number</td>
      <td style="width:222px">Number of alerts related to the artifact.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.file_artifacts.is_malicious</td>
      <td style="width:44px">boolean</td>
      <td style="width:222px">
        Whether the artifact is malicious, decided by the Wildfire verdict.
      </td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.file_artifacts.is_manual</td>
      <td style="width:44px">boolean</td>
      <td style="width:222px">Whether the artifact was created by the user (manually).</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.file_artifacts.type</td>
      <td style="width:44px">String</td>
      <td style="width:222px">The artifact type, for example, hash.</td>
    </tr>
    <tr>
      <td style="width:514px">PaloAltoNetworksXDR.Incident.file_artifacts.file_sha256</td>
      <td style="width:44px">String</td>
      <td style="width:222px">SHA-256 hash of the file</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!xdr-get-incident-extra-data incident_id="1" alerts_limit="10"</pre>
<h5>Context Example</h5>
<pre>{
    "PaloAltoNetworksXDR.Incident": {
        "host_count": 6, 
        "manual_severity": null, 
        "xdr_url": "https://1111.paloaltonetworks.com/incident-view/1", 
        "assigned_user_pretty_name": "Michael Foo", 
        "alert_count": 9, 
        "med_severity_alert_count": 5, 
        "detection_time": null, 
        "user_count": 1, 
        "severity": "high", 
        "alerts": [
            {
                "category": "Vulnerability", 
                "action_pretty": "Detected (Raised An Alert)", 
                "description": "Vulnerability Exploit Detection", 
                "severity": "high", 
                "host_ip": "10.54.12.6", 
                "source": "PAN NGFW", 
                "alert_id": "1", 
                "host_name": "10.54.12.6", 
                "detection_timestamp": 1564408244000, 
                "action": "DETECTED_4", 
                "user_name": null, 
                "name": "SMB: User Password Brute Force Attempt"
            }, 
            {
                "category": "Vulnerability", 
                "action_pretty": "Detected (Raised An Alert)", 
                "description": "Vulnerability Exploit Detection (#BLVFILE3)", 
                "severity": "medium", 
                "host_ip": "10.54.12.6", 
                "source": "PAN NGFW", 
                "alert_id": "21", 
                "host_name": "10.54.12.6, 
                "detection_timestamp": 1564422346000, 
                "action": "DETECTED_4", 
                "user_name": null, 
                "name": "Microsoft Windows RPC Fragment Evasion Attempt"
            }, 
            {
                "category": "Vulnerability", 
                "action_pretty": "Detected (Raised An Alert)", 
                "description": "Vulnerability Exploit Detection", 
                "severity": "high", 
                "host_ip": "10.54.12.6", 
                "source": "PAN NGFW", 
                "alert_id": "26", 
                "host_name": "10.54.12.6", 
                "detection_timestamp": 1564431024000, 
                "action": "DETECTED_4", 
                "user_name": null, 
                "name": "SMB: User Password Brute Force Attempt"
            }, 
            {
                "category": "Vulnerability", 
                "action_pretty": "Detected (Raised An Alert)", 
                "description": "Vulnerability Exploit Detection", 
                "severity": "medium", 
                "host_ip": "10.54.12.6", 
                "source": "PAN NGFW", 
                "alert_id": "44", 
                "host_name": "10.54.12.6", 
                "detection_timestamp": 1564480944000, 
                "action": "DETECTED_4", 
                "user_name": null, 
                "name": "Microsoft Windows RPC Fragment Evasion Attempt"
            }, 
            {
                "category": "Vulnerability", 
                "action_pretty": "Detected (Raised An Alert)", 
                "description": "Vulnerability Exploit Detection", 
                "severity": "high", 
                "host_ip": "10.54.12.6", 
                "source": "PAN NGFW", 
                "alert_id": "83", 
                "host_name": "10.54.12.6", 
                "detection_timestamp": 1564681179000, 
                "action": "DETECTED_4", 
                "user_name": null, 
                "name": "SMB: User Password Brute Force Attempt"
            }, 
            {
                "category": "Vulnerability", 
                "action_pretty": "Detected (Raised An Alert)", 
                "description": "Vulnerability Exploit Detection (#BLVFILE3)", 
                "severity": "medium", 
                "host_ip": "10.54.12.6", 
                "source": "PAN NGFW", 
                "alert_id": "113", 
                "host_name": "10.54.12.6", 
                "detection_timestamp": 1564868791000, 
                "action": "DETECTED_4", 
                "user_name": null, 
                "name": "Microsoft Windows RPC Fragment Evasion Attempt"
            }, 
            {
                "category": "Vulnerability", 
                "action_pretty": "Detected (Raised An Alert)", 
                "description": "Vulnerability Exploit Detection", 
                "severity": "high", 
                "host_ip": "10.54.12.6", 
                "source": "PAN NGFW", 
                "alert_id": "121", 
                "host_name": "10.54.12.6", 
                "detection_timestamp": 1564943165000, 
                "action": "DETECTED_4", 
                "user_name": null, 
                "name": "SMB: User Password Brute Force Attempt"
            }, 
            {
                "category": "Vulnerability", 
                "action_pretty": "Detected (Raised An Alert)", 
                "description": "Vulnerability Exploit Detection", 
                "severity": "medium", 
                "host_ip": "10.54.12.6", 
                "source": "PAN NGFW", 
                "alert_id": "135", 
                "host_name": "10.54.12.6", 
                "detection_timestamp": 1565027542000, 
                "action": "DETECTED_4", 
                "user_name": null, 
                "name": "Microsoft Windows RPC Fragment Evasion Attempt"
            }, 
            {
                "category": "Vulnerability", 
                "action_pretty": "Detected (Raised An Alert)", 
                "description": "Vulnerability Exploit Detection", 
                "severity": "medium", 
                "host_ip": "10.54.12.6", 
                "source": "PAN NGFW", 
                "alert_id": "480", 
                "host_name": "10.54.12.6", 
                "detection_timestamp": 1565238356000, 
                "action": "DETECTED_4", 
                "user_name": null, 
                "name": "Microsoft Windows RPC Fragment Evasion Attempt"
            }
        ], 
        "low_severity_alert_count": 0, 
        "status": "resolved_false_positive", 
        "description": "'SMB: User Password Brute Force Attempt' along with 8 other alerts generated by PAN NGFW detected on 6 hosts", 
        "resolve_comment": "some comment", 
        "creation_time": 1564423080364, 
        "modification_time": 1566994926897, 
        "network_artifacts": [
            {
                "network_remote_port": 445, 
                "alert_count": 9, 
                "network_remote_ip": "10.54.12.6", 
                "is_manual": false, 
                "network_domain": null, 
                "type": "IP", 
                "network_country": null
            }
        ], 
        "file_artifacts": [], 
        "manual_description": null, 
        "incident_id": "1", 
        "notes": null, 
        "assigned_user_mail": "foo@demisto.com", 
        "high_severity_alert_count": 4
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Incident 1</h3>
<table>
  <thead>
    <tr>
      <th>alert_count</th>
      <th>assigned_user_mail</th>
      <th>assigned_user_pretty_name</th>
      <th>creation_time</th>
      <th>description</th>
      <th>detection_time</th>
      <th>high_severity_alert_count</th>
      <th>host_count</th>
      <th>incident_id</th>
      <th>low_severity_alert_count</th>
      <th>manual_description</th>
      <th>manual_severity</th>
      <th>med_severity_alert_count</th>
      <th>modification_time</th>
      <th>notes</th>
      <th>resolve_comment</th>
      <th>severity</th>
      <th>status</th>
      <th>user_count</th>
      <th>xdr_url</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>9</td>
      <td>
        <a href="mailto:foo@demisto.com">foo@demisto.com</a>
      </td>
      <td>Michael Foo</td>
      <td>1564423080364</td>
      <td>
        'SMB: User Password Brute Force Attempt' along with 8 other alerts
        generated by PAN NGFW detected on 6 hosts
      </td>
      <td>&nbsp;</td>
      <td>4</td>
      <td>6</td>
      <td>1</td>
      <td>0</td>
      <td>&nbsp;</td>
      <td>&nbsp;</td>
      <td>5</td>
      <td>1566994926897</td>
      <td>&nbsp;</td>
      <td>some comment</td>
      <td>high</td>
      <td>resolved_false_positive</td>
      <td>1</td>
      <td>
        <a href="https://1111.paloaltonetworks.com/incident-view/1" rel="nofollow">https://1111.paloaltonetworks.com/incident-view/1</a>
      </td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3>Alerts</h3>
<table>
  <thead>
    <tr>
      <th>action</th>
      <th>action_pretty</th>
      <th>alert_id</th>
      <th>category</th>
      <th>description</th>
      <th>detection_timestamp</th>
      <th>host_ip</th>
      <th>host_name</th>
      <th>name</th>
      <th>severity</th>
      <th>source</th>
      <th>user_name</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>DETECTED_4</td>
      <td>Detected (Raised An Alert)</td>
      <td>1</td>
      <td>Vulnerability</td>
      <td>Vulnerability Exploit Detection</td>
      <td>1564408244000</td>
      <td>10.54.12.6</td>
      <td>10.54.12.6</td>
      <td>SMB: User Password Brute Force Attempt</td>
      <td>high</td>
      <td>PAN NGFW</td>
      <td>&nbsp;</td>
    </tr>
    <tr>
      <td>DETECTED_4</td>
      <td>Detected (Raised An Alert)</td>
      <td>21</td>
      <td>Vulnerability</td>
      <td>Vulnerability Exploit Detection (#BLVFILE3)</td>
      <td>1564422346000</td>
      <td>10.54.12.6</td>
      <td>10.54.12.6</td>
      <td>Microsoft Windows RPC Fragment Evasion Attempt</td>
      <td>medium</td>
      <td>PAN NGFW</td>
      <td>&nbsp;</td>
    </tr>
    <tr>
      <td>DETECTED_4</td>
      <td>Detected (Raised An Alert)</td>
      <td>26</td>
      <td>Vulnerability</td>
      <td>Vulnerability Exploit Detection</td>
      <td>1564431024000</td>
      <td>10.54.12.6</td>
      <td>10.54.12.6</td>
      <td>SMB: User Password Brute Force Attempt</td>
      <td>high</td>
      <td>PAN NGFW</td>
      <td>&nbsp;</td>
    </tr>
    <tr>
      <td>DETECTED_4</td>
      <td>Detected (Raised An Alert)</td>
      <td>44</td>
      <td>Vulnerability</td>
      <td>Vulnerability Exploit Detection</td>
      <td>1564480944000</td>
      <td>10.54.12.6</td>
      <td>10.54.12.6</td>
      <td>Microsoft Windows RPC Fragment Evasion Attempt</td>
      <td>medium</td>
      <td>PAN NGFW</td>
      <td>&nbsp;</td>
    </tr>
    <tr>
      <td>DETECTED_4</td>
      <td>Detected (Raised An Alert)</td>
      <td>83</td>
      <td>Vulnerability</td>
      <td>Vulnerability Exploit Detection</td>
      <td>1564681179000</td>
      <td>10.54.12.6</td>
      <td>10.54.12.6</td>
      <td>SMB: User Password Brute Force Attempt</td>
      <td>high</td>
      <td>PAN NGFW</td>
      <td>&nbsp;</td>
    </tr>
    <tr>
      <td>DETECTED_4</td>
      <td>Detected (Raised An Alert)</td>
      <td>113</td>
      <td>Vulnerability</td>
      <td>Vulnerability Exploit Detection (#BLVFILE3)</td>
      <td>1564868791000</td>
      <td>10.54.12.6</td>
      <td>10.54.12.6</td>
      <td>Microsoft Windows RPC Fragment Evasion Attempt</td>
      <td>medium</td>
      <td>PAN NGFW</td>
      <td>&nbsp;</td>
    </tr>
    <tr>
      <td>DETECTED_4</td>
      <td>Detected (Raised An Alert)</td>
      <td>121</td>
      <td>Vulnerability</td>
      <td>Vulnerability Exploit Detection</td>
      <td>1564943165000</td>
      <td>10.54.12.6</td>
      <td>10.54.12.6</td>
      <td>SMB: User Password Brute Force Attempt</td>
      <td>high</td>
      <td>PAN NGFW</td>
      <td>&nbsp;</td>
    </tr>
    <tr>
      <td>DETECTED_4</td>
      <td>Detected (Raised An Alert)</td>
      <td>135</td>
      <td>Vulnerability</td>
      <td>Vulnerability Exploit Detection</td>
      <td>1565027542000</td>
      <td>10.54.12.6</td>
      <td>10.54.12.6</td>
      <td>Microsoft Windows RPC Fragment Evasion Attempt</td>
      <td>medium</td>
      <td>PAN NGFW</td>
      <td>&nbsp;</td>
    </tr>
    <tr>
      <td>DETECTED_4</td>
      <td>Detected (Raised An Alert)</td>
      <td>480</td>
      <td>Vulnerability</td>
      <td>Vulnerability Exploit Detection</td>
      <td>1565238356000</td>
      <td>10.54.12.6</td>
      <td>10.54.12.6</td>
      <td>Microsoft Windows RPC Fragment Evasion Attempt</td>
      <td>medium</td>
      <td>PAN NGFW</td>
      <td>&nbsp;</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3>Network Artifacts</h3>
<table>
  <thead>
    <tr>
      <th>alert_count</th>
      <th>is_manual</th>
      <th>network_country</th>
      <th>network_domain</th>
      <th>network_remote_ip</th>
      <th>network_remote_port</th>
      <th>type</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>9</td>
      <td>false</td>
      <td>&nbsp;</td>
      <td>&nbsp;</td>
      <td>10.54.12.6</td>
      <td>445</td>
      <td>IP</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h3>File Artifacts</h3>
<p>
  <strong>No entries.</strong>
</p>
<h3 id="h_2044c2ca-8897-4439-9623-e3d25248df47">3. Update an incident</h3>
<hr>
<p>
  Updates one or more fields of a specified incident. Missing fields will be ignored.
  To remove the assignment for an incident, pass a null value in assignee email
  argument.
</p>
<h5>Required Permissions</h5>
<p>
  <strong>FILL IN REQUIRED PERMISSIONS HERE</strong>
</p>
<h5>Base Command</h5>
<p>
  <code>xdr-update-incident</code>
</p>
<h5>Input</h5>
<table style="width:749px">
  <thead>
    <tr>
      <th style="width:208px">
        <strong>Argument Name</strong>
      </th>
      <th style="width:461px">
        <strong>Description</strong>
      </th>
      <th style="width:71px">
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="width:208px">incident_id</td>
      <td style="width:461px">
        XDR incident ID. You can get the incident ID from the output of the
        'xdr-get-incidents' command or the 'xdr-get-incident-extra-details'
        command.
      </td>
      <td style="width:71px">Required</td>
    </tr>
    <tr>
      <td style="width:208px">manual_severity</td>
      <td style="width:461px">Severity to assign to the incident (LOW, MEDIUM, or HIGH).</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:208px">assigned_user_mail</td>
      <td style="width:461px">Email address of the user to assigned to the incident.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:208px">assigned_user_pretty_name</td>
      <td style="width:461px">Full name of the user assigned to the incident.</td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:208px">status</td>
      <td style="width:461px">
        Status of the incident (NEW, UNDER_INVESTIGATION, RESOLVED_THREAT_HANDLED,
        RESOLVED_KNOWN_ISSUE, RESOLVED_DUPLICATE, RESOLVED_FALSE_POSITIVE,
        RESOLVED_OTHER).
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:208px">resolve_comment</td>
      <td style="width:461px">
        Comment explaining why the incident was resolved. This should be
        set when the incident is resolved.
      </td>
      <td style="width:71px">Optional</td>
    </tr>
    <tr>
      <td style="width:208px">unassign_user</td>
      <td style="width:461px">If true, will remove all assigned users from the incident.</td>
      <td style="width:71px">Optional</td>
    </tr>
  </tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!xdr-update-incident incident_id="1" status="RESOLVED_FALSE_POSITIVE" resolve_comment="some comment"</pre>
<h5>Human Readable Output</h5>
<p>Incident 1 has been updated</p>